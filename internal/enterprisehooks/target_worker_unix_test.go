//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// targetWorkerTestSwapEnv tells a worker started by these tests to replace
// one path with a symlink immediately before a repair helper changes it,
// the way a target user racing the repair would. Only this test binary
// reads it, and only tests add it to the worker environment allowlist.
const targetWorkerTestSwapEnv = "DEFENSECLAW_TEST_TARGET_WORKER_SWAP"

type targetWorkerTestSwap struct {
	// Trigger is the path the repair helper is about to change.
	Trigger string `json:"trigger"`
	// Replace is moved aside and becomes a symlink to Destination. It is
	// Trigger itself or one of its parent directories.
	Replace     string `json:"replace"`
	Destination string `json:"destination"`
}

const (
	testTargetOperationIdentity = "enterprise-hooks.test.identity"
	testTargetOperationFail     = "enterprise-hooks.test.fail"
	testTargetOperationSleep    = "enterprise-hooks.test.sleep"
	// testTargetOperationPause returns after the payload's milliseconds, as
	// a worker the target user stops and resumes just before its deadline.
	testTargetOperationPause = "enterprise-hooks.test.pause"
)

type testTargetIdentity struct {
	UID           int      `json:"uid"`
	EUID          int      `json:"euid"`
	GID           int      `json:"gid"`
	EGID          int      `json:"egid"`
	Groups        []int    `json:"groups"`
	CanRegainRoot bool     `json:"can_regain_root"`
	Dumpable      int      `json:"dumpable"`
	SavedIDsErr   string   `json:"saved_ids_err,omitempty"`
	Home          string   `json:"home"`
	Env           []string `json:"env"`
	Echo          string   `json:"echo"`
	BinaryVersion string   `json:"binary_version"`
}

func init() {
	RegisterTargetOperation(testTargetOperationIdentity, func(_ context.Context, target TargetCredentials, payload json.RawMessage) (any, error) {
		var echo string
		if err := DecodeTargetOperationRequest(payload, &echo); err != nil {
			return nil, err
		}
		groups, err := syscall.Getgroups()
		if err != nil {
			return nil, err
		}
		identity := testTargetIdentity{
			UID: os.Getuid(), EUID: os.Geteuid(), GID: os.Getgid(), EGID: os.Getegid(),
			Groups: groups, Dumpable: testProcessDumpable(), Home: target.UserHome,
			Env: os.Environ(), Echo: echo, BinaryVersion: version.Current().BinaryVersion,
		}
		if err := verifySavedTargetIDs(target.UID, target.GID); err != nil {
			identity.SavedIDsErr = err.Error()
		}
		if err := syscall.Seteuid(0); err == nil {
			identity.CanRegainRoot = true
		}
		return identity, nil
	})
	RegisterTargetOperation(testTargetOperationFail, func(_ context.Context, _ TargetCredentials, payload json.RawMessage) (any, error) {
		var reason string
		if err := DecodeTargetOperationRequest(payload, &reason); err != nil {
			return nil, err
		}
		return nil, errors.New(reason)
	})
	RegisterTargetOperation(testTargetOperationSleep, func(ctx context.Context, _ TargetCredentials, _ json.RawMessage) (any, error) {
		select {
		case <-ctx.Done():
		case <-time.After(time.Minute):
		}
		return struct{}{}, nil
	})
	RegisterTargetOperation(testTargetOperationPause, func(_ context.Context, _ TargetCredentials, payload json.RawMessage) (any, error) {
		var milliseconds int
		if err := DecodeTargetOperationRequest(payload, &milliseconds); err != nil {
			return nil, err
		}
		time.Sleep(time.Duration(milliseconds) * time.Millisecond)
		return struct{}{}, nil
	})
}

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == targetWorkerArg {
		installTargetWorkerTestSwap()
	}
	if handled, code := RunTargetWorkerIfRequested(); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func installTargetWorkerTestSwap() {
	raw := os.Getenv(targetWorkerTestSwapEnv)
	if raw == "" {
		return
	}
	var swap targetWorkerTestSwap
	if err := json.Unmarshal([]byte(raw), &swap); err != nil {
		fmt.Fprintf(os.Stderr, "invalid %s: %v\n", targetWorkerTestSwapEnv, err)
		os.Exit(targetWorkerExitProtocol)
	}
	var once sync.Once
	beforeTargetPathMutation = func(path string) {
		if path != swap.Trigger {
			return
		}
		once.Do(func() {
			if err := os.Rename(swap.Replace, swap.Replace+".moved"); err != nil {
				fmt.Fprintf(os.Stderr, "test swap: move %s aside: %v\n", swap.Replace, err)
				return
			}
			if err := os.Symlink(swap.Destination, swap.Replace); err != nil {
				fmt.Fprintf(os.Stderr, "test swap: symlink %s: %v\n", swap.Replace, err)
			}
		})
	}
}

func stubTargetProcessEUID(t *testing.T, euid int) {
	t.Helper()
	original := targetProcessEUID
	targetProcessEUID = func() int { return euid }
	t.Cleanup(func() { targetProcessEUID = original })
}

func stubBeforeTargetPathMutation(t *testing.T, hook func(string)) {
	t.Helper()
	original := beforeTargetPathMutation
	beforeTargetPathMutation = hook
	t.Cleanup(func() { beforeTargetPathMutation = original })
}

// setGuardianBinaryVersion records a release version in this (guardian)
// process the way CLI startup does; the worker never runs CLI startup.
func setGuardianBinaryVersion(t *testing.T, value string) {
	t.Helper()
	previous := version.Current().BinaryVersion
	version.SetBinaryVersion(value)
	t.Cleanup(func() { version.SetBinaryVersion(previous) })
}

func currentTestTarget(t *testing.T) TargetCredentials {
	t.Helper()
	skipIfRoot(t)
	return TargetCredentials{UserHome: newTestHome(t), UID: os.Getuid(), GID: os.Getgid()}
}

func codexInstallOptions(home string, uid, gid int) InstallOptions {
	return InstallOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      uid,
		OwnerGID:      gid,
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      "codex-token",
		GuardrailMode: "action",
		HookFailMode:  "closed",
		AgentVersion:  "codex-cli 0.142.0",
		Registry:      connector.NewDefaultRegistry(),
	}
}

func TestWithOwnerCredentialsNeverBorrowsTargetIdentityInRootProcess(t *testing.T) {
	skipIfRoot(t)
	stubTargetProcessEUID(t, 0)
	home := newTestHome(t)
	called := false
	err := withOwnerCredentials(os.Getuid(), os.Getgid(), func() error {
		called = true
		return nil
	})
	if !errors.Is(err, errRootTargetPathOperation) || called {
		t.Fatalf("withOwnerCredentials as root = %v (ran fn=%v), want refusal without running fn", err, called)
	}
	err = RunAsTarget(TargetCredentials{UserHome: home, UID: os.Getuid(), GID: os.Getgid()}, func() error {
		called = true
		return nil
	})
	if !errors.Is(err, errRootTargetPathOperation) || called {
		t.Fatalf("RunAsTarget as root = %v (ran fn=%v), want refusal without running fn", err, called)
	}
}

func TestRepairHelpersRefuseToChangeTargetPathsFromRootProcess(t *testing.T) {
	stubTargetProcessEUID(t, 0)
	stubBeforeTargetPathMutation(t, func(path string) {
		t.Fatalf("repair helper reached the mutation step for %s in a root process", path)
	})
	dir := newTestHome(t)
	file := filepath.Join(dir, "config")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := chmodOwnedPath(file, 0o600); !errors.Is(err, errRootTargetPathOperation) {
		t.Fatalf("chmodOwnedPath as root = %v, want refusal", err)
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o666 {
		t.Fatalf("mode after refused chmod = %v, %v; want unchanged 0666", info.Mode().Perm(), err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := removeRepairSymlink(link, os.Getuid(), "hook config"); !errors.Is(err, errRootTargetPathOperation) {
		t.Fatalf("removeRepairSymlink as root = %v, want refusal", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink removed by a refused repair: %v", err)
	}
}

func TestRootInstallAndVerifyDelegateToTargetWorker(t *testing.T) {
	target := currentTestTarget(t)
	stubTargetProcessEUID(t, 0)
	opts := codexInstallOptions(target.UserHome, target.UID, target.GID)
	opts.OTLPPathToken = strings.Repeat("d", 64)
	opts.HILTEnabled = true
	opts.HookContractID = "codex-contract"
	opts.RecoveryHookContractLockUpdatedAt = "2026-09-26T00:00:00Z"
	opts.RecoveryHookContractEntryUpdatedAt = "2026-09-26T00:00:01Z"
	opts.WorkspaceDir = filepath.Join(target.UserHome, "work")
	opts.AllowMissingHookConfigRepair = true
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")

	type call struct {
		target    TargetCredentials
		operation string
		options   InstallOptions
	}
	var calls []call
	reply := InstallResult{Connector: "codex", UserHome: target.UserHome, DataDir: dataDir, HookContractID: "codex-contract"}
	original := targetWorkerRunner
	targetWorkerRunner = func(_ context.Context, workerTarget TargetCredentials, operation string, payload json.RawMessage) (json.RawMessage, error) {
		options, err := decodeTargetInstallRequest(workerTarget, payload)
		if err != nil {
			return nil, err
		}
		calls = append(calls, call{target: workerTarget, operation: operation, options: options})
		return json.Marshal(reply)
	}
	t.Cleanup(func() { targetWorkerRunner = original })

	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("root Install: %v", err)
	}
	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("root Verify: %v", err)
	}
	if len(calls) != 2 || calls[0].operation != targetOperationInstall || calls[1].operation != targetOperationVerify {
		t.Fatalf("worker calls = %+v, want install then verify", calls)
	}
	for _, got := range calls {
		if got.target != (TargetCredentials{UserHome: target.UserHome, UID: target.UID, GID: target.GID}) {
			t.Fatalf("worker target = %+v, want %+v", got.target, target)
		}
		want := opts
		want.Registry, got.options.Registry = nil, nil
		if !reflect.DeepEqual(got.options, want) {
			t.Fatalf("worker options = %+v\nwant %+v", got.options, want)
		}
	}

	// The worker runs as the target user, so the guardian binds its answer to
	// the target it asked about.
	reply.UserHome = t.TempDir()
	if _, err := Install(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "different target") {
		t.Fatalf("Install accepted a worker result for another home: %v", err)
	}
}

// Every InstallOptions field must be carried to the worker or be deliberately
// rebuilt or ignored there; a new option that silently disappears would make
// the root guardian install something other than what it was asked to.
func TestTargetInstallRequestCarriesEveryInstallOption(t *testing.T) {
	notCarried := map[string]string{
		"Registry": "rebuilt from the built-in connectors in the worker",
		"OwnerSID": "Windows-only target identity",
		// Machine-policy inputs consumed only by the native Windows installer.
		"ClaudeCodeAllowUnmanagedHooks": "native Windows only",
		"CursorApprovedForeignHooks":    "native Windows only",
	}
	request := reflect.TypeOf(targetInstallRequest{})
	carried := map[string]reflect.Type{}
	for i := 0; i < request.NumField(); i++ {
		carried[request.Field(i).Name] = request.Field(i).Type
	}
	options := reflect.TypeOf(InstallOptions{})
	for i := 0; i < options.NumField(); i++ {
		field := options.Field(i)
		if _, skip := notCarried[field.Name]; skip {
			continue
		}
		typ, ok := carried[field.Name]
		if !ok {
			t.Errorf("InstallOptions.%s is not carried to the per-target worker", field.Name)
			continue
		}
		if typ != field.Type {
			t.Errorf("InstallOptions.%s is %s but the worker request carries %s", field.Name, field.Type, typ)
		}
	}
}

func TestTargetWorkerEnvironmentCarriesOnlyAllowlistedSettings(t *testing.T) {
	home := newTestHome(t)
	t.Setenv("DEFENSECLAW_HOME", "/opt/example/defenseclaw")
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
	t.Setenv("DEFENSECLAW_TEST_UNLISTED_SECRET", "must-not-pass")
	t.Setenv("CLAUDE_CONFIG_DIR", "/elsewhere")
	t.Setenv("LD_PRELOAD", "/tmp/preload.so")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/tmp/preload.dylib")
	env := targetWorkerEnvironment(TargetCredentials{UserHome: home, UID: os.Getuid(), GID: os.Getgid()})
	for _, want := range []string{
		"HOME=" + home,
		"DEFENSECLAW_HOME=/opt/example/defenseclaw",
		"DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise",
	} {
		if !slices.Contains(env, want) {
			t.Errorf("worker environment is missing %q: %v", want, env)
		}
	}
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "HOME", "PATH", "USER", "LOGNAME":
			continue
		}
		if !slices.Contains(targetWorkerPassthroughEnv, name) {
			t.Errorf("worker environment carries non-allowlisted %q", entry)
		}
	}
}

func TestTargetWorkerMainRejectsMalformedRequestsBeforeChangingIdentity(t *testing.T) {
	home := newTestHome(t)
	valid := func(mutate func(*targetWorkerRequest)) string {
		request := targetWorkerRequest{
			Version: targetWorkerProtocolVersion, Operation: testTargetOperationIdentity,
			UID: 1000, GID: 1000, Home: home, Payload: json.RawMessage(`"x"`),
		}
		mutate(&request)
		data, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	cases := map[string]string{
		"not json":          "{",
		"unknown field":     `{"version":1,"operation":"x","uid":1000,"gid":1000,"home":"/h","payload":null,"extra":1}`,
		"trailing data":     valid(func(*targetWorkerRequest) {}) + " {}",
		"protocol version":  valid(func(r *targetWorkerRequest) { r.Version = 2 }),
		"root target":       valid(func(r *targetWorkerRequest) { r.UID = 0 }),
		"negative gid":      valid(func(r *targetWorkerRequest) { r.GID = -1 }),
		"relative home":     valid(func(r *targetWorkerRequest) { r.Home = "home/user" }),
		"unclean home":      valid(func(r *targetWorkerRequest) { r.Home = home + "/../" + filepath.Base(home) }),
		"filesystem root":   valid(func(r *targetWorkerRequest) { r.Home = "/" }),
		"unknown operation": valid(func(r *targetWorkerRequest) { r.Operation = "enterprise-hooks.test.missing" }),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runTargetWorkerMain(strings.NewReader(input), &stdout, &stderr)
			if code != targetWorkerExitProtocol {
				t.Fatalf("exit code = %d, want %d", code, targetWorkerExitProtocol)
			}
			var response targetWorkerResponse
			if err := decodeTargetOperationJSON(stdout.Bytes(), &response); err != nil {
				t.Fatalf("decode response %q: %v", stdout.String(), err)
			}
			if response.OK || response.Error == "" || response.Version != targetWorkerProtocolVersion {
				t.Fatalf("response = %+v, want a versioned refusal", response)
			}
		})
	}
}

func TestSpawnTargetWorkerRequiresWorkerEntrypoint(t *testing.T) {
	target := currentTestTarget(t)
	targetWorkerEntrypointReady.Store(false)
	t.Cleanup(func() { targetWorkerEntrypointReady.Store(true) })
	if _, err := spawnTargetWorker(context.Background(), target, testTargetOperationIdentity, json.RawMessage(`"x"`)); !errors.Is(err, errTargetWorkerNoEntry) {
		t.Fatalf("spawnTargetWorker without a worker entrypoint = %v, want %v", err, errTargetWorkerNoEntry)
	}
}

func TestTargetWorkerSubprocessRunsOperationAsTarget(t *testing.T) {
	target := currentTestTarget(t)
	t.Setenv("DEFENSECLAW_TEST_UNLISTED_SECRET", "must-not-pass")
	setGuardianBinaryVersion(t, "9.8.7-worker-test")
	var identity testTargetIdentity
	if err := runTargetOperationInWorkerForTest(t, target, testTargetOperationIdentity, "hello", &identity); err != nil {
		t.Fatalf("worker identity operation: %v", err)
	}
	if identity.UID != target.UID || identity.EUID != target.UID || identity.GID != target.GID || identity.EGID != target.GID {
		t.Fatalf("worker identity = %+v, want uid/gid %d/%d", identity, target.UID, target.GID)
	}
	if identity.CanRegainRoot || identity.SavedIDsErr != "" {
		t.Fatalf("worker identity = %+v, want no path back to root", identity)
	}
	if identity.Home != target.UserHome || identity.Echo != "hello" {
		t.Fatalf("worker saw home %q payload %q", identity.Home, identity.Echo)
	}
	if identity.BinaryVersion != "9.8.7-worker-test" {
		t.Fatalf("worker binary version = %q, want the guardian's 9.8.7-worker-test", identity.BinaryVersion)
	}
	if runtime.GOOS == "linux" && identity.Dumpable != 0 {
		t.Fatalf("worker dumpable = %d, want 0", identity.Dumpable)
	}
	for _, entry := range identity.Env {
		if strings.HasPrefix(entry, "DEFENSECLAW_TEST_UNLISTED_SECRET=") {
			t.Fatalf("worker inherited a non-allowlisted variable: %q", entry)
		}
	}
	if !slices.Contains(identity.Env, "HOME="+target.UserHome) {
		t.Fatalf("worker HOME is not the target home: %v", identity.Env)
	}
}

func TestTargetWorkerSubprocessReportsOperationErrorsAndDeadlines(t *testing.T) {
	target := currentTestTarget(t)
	err := runTargetOperationInWorkerForTest(t, target, testTargetOperationFail, "enterprise hooks: specific failure", nil)
	if err == nil || err.Error() != "enterprise hooks: specific failure" {
		t.Fatalf("worker failure = %v, want the operation's own message", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = spawnTargetWorker(ctx, target, testTargetOperationSleep, json.RawMessage(`null`))
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("hung worker = %v, want a deadline failure", err)
	}
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("hung worker was stopped after %s", elapsed)
	}
}

// runTargetOperationInWorkerForTest forces the worker path for an
// unprivileged test process, which may run a worker only for itself.
func runTargetOperationInWorkerForTest(t *testing.T, target TargetCredentials, name string, request, response any) error {
	t.Helper()
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := spawnTargetWorker(context.Background(), target, name, payload)
	if err != nil {
		return err
	}
	if response == nil {
		return nil
	}
	return decodeTargetOperationJSON(raw, response)
}

func TestTargetWorkerSubprocessInstallsAndVerifiesTarget(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	target := currentTestTarget(t)
	codexConfig := filepath.Join(target.UserHome, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(codexConfig, 0o666); err != nil {
		t.Fatal(err)
	}
	opts := codexInstallOptions(target.UserHome, target.UID, target.GID)
	opts.AllowMissingHookConfigRepair = true
	setGuardianBinaryVersion(t, "9.8.7-worker-test")
	result, err := installThroughTargetWorker(context.Background(), opts, targetOperationInstall)
	if err != nil {
		t.Fatalf("worker Install: %v", err)
	}
	requireHookContractLockVersion(t, target.UserHome, "codex", "9.8.7-worker-test")
	if result.Connector != "codex" || len(result.HookConfigPaths) != 1 || result.HookConfigPaths[0] != codexConfig {
		t.Fatalf("worker Install result = %+v", result)
	}
	for path, want := range map[string]os.FileMode{
		codexConfig: 0o600,
		filepath.Join(target.UserHome, ".defenseclaw"):                           0o700,
		filepath.Join(target.UserHome, ".defenseclaw", "hooks", "codex-hook.sh"): 0o700,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("mode %s = %04o, want %04o", path, got, want)
		}
	}
	opts.AllowMissingHookConfigRepair = false
	if _, err := installThroughTargetWorker(context.Background(), opts, targetOperationVerify); err != nil {
		t.Fatalf("worker Verify: %v", err)
	}
}

// requireHookContractLockVersion checks the release version a worker install
// recorded for connectorName in the target's hook contract lock.
func requireHookContractLockVersion(t *testing.T, home, connectorName, want string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".defenseclaw", "hook_contract_lock.json"))
	if err != nil {
		t.Fatalf("read hook contract lock: %v", err)
	}
	var lock struct {
		Connectors map[string]struct {
			DefenseClawVersion string `json:"defenseclaw_version"`
		} `json:"connectors"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatalf("decode hook contract lock: %v", err)
	}
	if got := lock.Connectors[connectorName].DefenseClawVersion; got != want {
		t.Fatalf("hook contract lock %s defenseclaw_version = %q, want the guardian's %q", connectorName, got, want)
	}
}

// A target that swaps a checked path for a symlink before the repair changes
// it only redirects the change to something its own permissions allow.
func TestRepairSwapIsCheckedAgainstTargetPermissions(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	skipIfRoot(t)
	dir := newTestHome(t)

	t.Run("chmod", func(t *testing.T) {
		foreign := rootOwnedSystemFile(t)
		before, err := os.Stat(foreign)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		stubBeforeTargetPathMutation(t, func(changing string) {
			if changing != path || os.Geteuid() == 0 {
				return
			}
			_ = os.Remove(path)
			if err := os.Symlink(foreign, path); err != nil {
				t.Errorf("swap: %v", err)
			}
		})
		if err := chmodOwnedPath(path, 0o600); err == nil {
			t.Fatal("chmod through a swapped symlink to a file the target does not own succeeded")
		}
		after, err := os.Stat(foreign)
		if err != nil || after.Mode() != before.Mode() {
			t.Fatalf("foreign file mode changed from %v to %v (%v)", before.Mode(), after.Mode(), err)
		}
	})

	t.Run("remove", func(t *testing.T) {
		parent := filepath.Join(dir, "hooks")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "codex-hook.sh")
		if err := os.Symlink("/nonexistent", link); err != nil {
			t.Fatal(err)
		}
		// A directory the target cannot write stands in for one it does not own.
		protected := filepath.Join(dir, "protected")
		if err := os.Mkdir(protected, 0o700); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(protected, "codex-hook.sh")
		if err := os.WriteFile(sentinel, []byte("sentinel"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(protected, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(protected, 0o700) })
		stubBeforeTargetPathMutation(t, func(changing string) {
			if changing != link || os.Geteuid() == 0 {
				return
			}
			if err := os.Rename(parent, parent+".moved"); err != nil {
				t.Errorf("swap: %v", err)
				return
			}
			if err := os.Symlink(protected, parent); err != nil {
				t.Errorf("swap: %v", err)
			}
		})
		if err := removeRepairSymlink(link, os.Getuid(), "footprint file"); err == nil {
			t.Fatal("symlink removal through a swapped parent succeeded in a directory the target cannot write")
		}
		if data, err := os.ReadFile(sentinel); err != nil || string(data) != "sentinel" {
			t.Fatalf("sentinel after swapped removal: %q, %v", data, err)
		}
	})
}

func rootOwnedSystemFile(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"/etc/hosts", "/etc/passwd", "/etc/group"} {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid == 0 && info.Mode().Perm() != 0o600 {
			return resolved
		}
	}
	t.Skip("no root-owned regular system file to stand in for a foreign file")
	return ""
}

// Root-only integration tests. Run the test binary with sudo; the invoking
// user (SUDO_UID) or DEFENSECLAW_TEST_TARGET_UID is the repair target.

type rootWorkerFixture struct {
	uid, gid    int
	base, home  string
	protected   string
	codexConfig string
	hookDir     string
}

func newRootWorkerFixture(t *testing.T) rootWorkerFixture {
	t.Helper()
	requireEnterpriseHookInstaller(t)
	if os.Geteuid() != 0 {
		t.Skip("requires root; run the test binary with sudo")
	}
	raw := strings.TrimSpace(os.Getenv("DEFENSECLAW_TEST_TARGET_UID"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("SUDO_UID"))
	}
	uid, err := strconv.Atoi(raw)
	if err != nil || uid <= 0 {
		t.Skip("requires a non-root target uid in DEFENSECLAW_TEST_TARGET_UID or SUDO_UID")
	}
	account, err := user.LookupId(raw)
	if err != nil {
		t.Fatalf("resolve target uid %d: %v", uid, err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		t.Fatalf("target primary gid %q: %v", account.Gid, err)
	}
	if runtime.GOOS != "linux" {
		// The default refuses a worker image an unprivileged user could
		// replace; this test binary lives in such a scratch directory.
		original := targetWorkerExecutable
		targetWorkerExecutable = func() (string, string, error) {
			executable, err := os.Executable()
			return executable, executable, err
		}
		t.Cleanup(func() { targetWorkerExecutable = original })
	}
	base := t.TempDir()
	// Root owns these directories; the target may traverse but not write.
	for _, dir := range []string{filepath.Dir(base), base} {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f := rootWorkerFixture{uid: uid, gid: gid, base: base, home: filepath.Join(base, "home")}
	f.codexConfig = filepath.Join(f.home, ".codex", "config.toml")
	f.hookDir = filepath.Join(f.home, ".defenseclaw", "hooks")
	f.mkdirTarget(t, f.home)
	f.mkdirTarget(t, filepath.Dir(f.codexConfig))
	f.writeTarget(t, f.codexConfig, "model = \"gpt-5\"\n", 0o600)
	f.protected = filepath.Join(base, "root-owned")
	if err := os.Mkdir(f.protected, 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f rootWorkerFixture) mkdirTarget(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, f.uid, f.gid); err != nil {
		t.Fatal(err)
	}
}

func (f rootWorkerFixture) writeTarget(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, f.uid, f.gid); err != nil {
		t.Fatal(err)
	}
}

func (f rootWorkerFixture) sentinel(t *testing.T, name string) (string, os.FileInfo) {
	t.Helper()
	path := filepath.Join(f.protected, name)
	if err := os.WriteFile(path, []byte("root-owned sentinel\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, info
}

func (f rootWorkerFixture) requireSentinelIntact(t *testing.T, path string, before os.FileInfo) {
	t.Helper()
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("root-owned sentinel %s is gone: %v", path, err)
	}
	st := after.Sys().(*syscall.Stat_t)
	if after.Mode() != before.Mode() || st.Uid != 0 {
		t.Fatalf("root-owned sentinel changed: mode %v -> %v, uid %d", before.Mode(), after.Mode(), st.Uid)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "root-owned sentinel\n" {
		t.Fatalf("root-owned sentinel content = %q, %v", data, err)
	}
}

func (f rootWorkerFixture) armSwap(t *testing.T, swap targetWorkerTestSwap) {
	t.Helper()
	data, err := json.Marshal(swap)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(targetWorkerTestSwapEnv, string(data))
	original := targetWorkerPassthroughEnv
	targetWorkerPassthroughEnv = append(slices.Clone(original), targetWorkerTestSwapEnv)
	t.Cleanup(func() { targetWorkerPassthroughEnv = original })
}

func (f rootWorkerFixture) repairOptions() InstallOptions {
	opts := codexInstallOptions(f.home, f.uid, f.gid)
	opts.AllowMissingHookConfigRepair = true
	return opts
}

func requireSymlink(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s was not swapped for a symlink during repair (%v); the race was not exercised", path, err)
	}
}

func TestRootGuardianRepairChmodSwapCannotReachRootOwnedFile(t *testing.T) {
	f := newRootWorkerFixture(t)
	sentinel, before := f.sentinel(t, "sentinel")
	if err := os.Chmod(f.codexConfig, 0o666); err != nil {
		t.Fatal(err)
	}
	f.armSwap(t, targetWorkerTestSwap{Trigger: f.codexConfig, Replace: f.codexConfig, Destination: sentinel})
	_, err := Install(context.Background(), f.repairOptions())
	requireSymlink(t, f.codexConfig)
	f.requireSentinelIntact(t, sentinel, before)
	if err == nil || !strings.Contains(err.Error(), "chmod") {
		t.Fatalf("repair after a chmod swap = %v, want the target's chmod to be refused", err)
	}
}

func TestRootGuardianRepairSymlinkRemovalSwapCannotRemoveRootOwnedEntry(t *testing.T) {
	f := newRootWorkerFixture(t)
	f.mkdirTarget(t, filepath.Join(f.home, ".defenseclaw"))
	f.mkdirTarget(t, f.hookDir)
	hookScript := filepath.Join(f.hookDir, "codex-hook.sh")
	if err := os.Symlink("/nonexistent", hookScript); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(hookScript, f.uid, f.gid); err != nil {
		t.Fatal(err)
	}
	sentinel, before := f.sentinel(t, "codex-hook.sh")
	f.armSwap(t, targetWorkerTestSwap{Trigger: hookScript, Replace: f.hookDir, Destination: f.protected})
	_, err := Install(context.Background(), f.repairOptions())
	requireSymlink(t, f.hookDir)
	f.requireSentinelIntact(t, sentinel, before)
	if err == nil || !strings.Contains(err.Error(), "remove symlink") {
		t.Fatalf("repair after a parent swap = %v, want the target's removal to be refused", err)
	}
}

func TestRootGuardianRepairsThroughWorkerWithoutChangingItsOwnCredentials(t *testing.T) {
	f := newRootWorkerFixture(t)
	if err := os.Chmod(f.codexConfig, 0o666); err != nil {
		t.Fatal(err)
	}
	groups, err := syscall.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	egid := os.Getegid()
	var drift atomic.Value
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			select {
			case <-stop:
				return
			default:
			}
			current, _ := syscall.Getgroups()
			if os.Geteuid() != 0 || os.Getegid() != egid || !slices.Equal(current, groups) {
				drift.Store(fmt.Sprintf("euid=%d egid=%d groups=%v", os.Geteuid(), os.Getegid(), current))
			}
			runtime.Gosched()
		}
	}()
	setGuardianBinaryVersion(t, "9.8.7-root-worker-test")
	result, installErr := Install(context.Background(), f.repairOptions())
	_, verifyErr := Verify(context.Background(), codexInstallOptions(f.home, f.uid, f.gid))
	var identity testTargetIdentity
	identityErr := RunTargetOperation(context.Background(), TargetCredentials{UserHome: f.home, UID: f.uid, GID: f.gid},
		testTargetOperationIdentity, "root", &identity)
	close(stop)
	<-sampled
	if installErr != nil || verifyErr != nil || identityErr != nil {
		t.Fatalf("root repair via worker: install=%v verify=%v identity=%v", installErr, verifyErr, identityErr)
	}
	if value := drift.Load(); value != nil {
		t.Fatalf("guardian credentials changed while the worker ran: %v", value)
	}
	called := false
	if err := withOwnerCredentials(f.uid, f.gid, func() error { called = true; return nil }); !errors.Is(err, errRootTargetPathOperation) || called {
		t.Fatalf("in-process credential switch as root = %v (ran=%v), want refusal", err, called)
	}

	if result.UserHome != f.home || len(result.HookConfigPaths) != 1 {
		t.Fatalf("root Install result = %+v", result)
	}
	requireHookContractLockVersion(t, f.home, "codex", "9.8.7-root-worker-test")
	if identity.BinaryVersion != "9.8.7-root-worker-test" {
		t.Fatalf("root worker binary version = %q, want the guardian's", identity.BinaryVersion)
	}
	if identity.UID != f.uid || identity.EUID != f.uid || identity.GID != f.gid || identity.EGID != f.gid ||
		!slices.Equal(identity.Groups, []int{f.gid}) || identity.CanRegainRoot || identity.SavedIDsErr != "" {
		t.Fatalf("worker identity = %+v, want only uid %d gid %d", identity, f.uid, f.gid)
	}
	if runtime.GOOS == "linux" && identity.Dumpable != 0 {
		t.Fatalf("worker dumpable = %d, want 0", identity.Dumpable)
	}

	// Same files, owners and modes as an in-process install by the target.
	wantModes := map[string]os.FileMode{
		f.codexConfig:                         0o600,
		filepath.Join(f.home, ".defenseclaw"): 0o700,
		f.hookDir:                             0o700,
		filepath.Join(f.hookDir, "codex-hook.sh"): 0o700,
	}
	for path, want := range wantModes {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("mode %s = %04o, want %04o", path, got, want)
		}
	}
	if err := filepath.WalkDir(f.home, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if st := info.Sys().(*syscall.Stat_t); int(st.Uid) != f.uid || int(st.Gid) != f.gid {
			return fmt.Errorf("%s is owned by %d:%d, want %d:%d", path, st.Uid, st.Gid, f.uid, f.gid)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Resolving watch paths reads files in the target's home, so a root guardian
// resolves them only in the per-target worker and never in its own process.
func TestRootWatchPathsResolveInTargetWorker(t *testing.T) {
	target := currentTestTarget(t)
	stubTargetProcessEUID(t, 0)
	opts := codexInstallOptions(target.UserHome, target.UID, target.GID)
	opts.AgentVersion = ""
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")

	if _, err := WatchDirs(opts); !errors.Is(err, errRootTargetPathOperation) {
		t.Fatalf("WatchDirs in a root process = %v, want refusal", err)
	}
	if _, err := WatchOwnedFiles(opts); !errors.Is(err, errRootTargetPathOperation) {
		t.Fatalf("WatchOwnedFiles in a root process = %v, want refusal", err)
	}

	reply := targetWatchPathsResult{
		Dirs:            []string{filepath.Join(target.UserHome, ".codex"), dataDir},
		ExclusiveWriter: []string{filepath.Join(dataDir, "hooks", "codex-hook.sh")},
		SharedWriter:    []string{filepath.Join(target.UserHome, ".codex", "config.toml")},
	}
	var operations []string
	original := targetWorkerRunner
	targetWorkerRunner = func(_ context.Context, workerTarget TargetCredentials, operation string, payload json.RawMessage) (json.RawMessage, error) {
		options, err := decodeTargetInstallRequest(workerTarget, payload)
		if err != nil {
			return nil, err
		}
		if workerTarget != (TargetCredentials{UserHome: target.UserHome, UID: target.UID, GID: target.GID}) || options.AgentVersion != "" {
			return nil, fmt.Errorf("worker asked for %+v with agent version %q", workerTarget, options.AgentVersion)
		}
		operations = append(operations, operation)
		return json.Marshal(reply)
	}
	t.Cleanup(func() { targetWorkerRunner = original })

	set := ResolveWatchPaths(context.Background(), opts)
	if !slices.Equal(operations, []string{targetOperationWatchPaths}) {
		t.Fatalf("worker operations = %v, want one %s", operations, targetOperationWatchPaths)
	}
	if set.DirsErr != nil || set.OwnershipErr != nil || !slices.Equal(set.Dirs, reply.Dirs) ||
		!slices.Equal(set.Ownership.ExclusiveWriter, reply.ExclusiveWriter) ||
		!slices.Equal(set.Ownership.SharedWriter, reply.SharedWriter) {
		t.Fatalf("root ResolveWatchPaths = %+v, want the worker's answer %+v", set, reply)
	}

	// Each half keeps its own error, as the in-process calls do.
	reply.Dirs, reply.DirsError = nil, "enterprise hooks: specific data dir failure"
	set = ResolveWatchPaths(context.Background(), opts)
	if set.DirsErr == nil || set.DirsErr.Error() != reply.DirsError || set.OwnershipErr != nil ||
		!slices.Equal(set.Ownership.SharedWriter, reply.SharedWriter) {
		t.Fatalf("root ResolveWatchPaths with a dirs failure = %+v", set)
	}

	// The guardian watches the returned directories itself, so one outside
	// the target home is refused.
	reply.DirsError = ""
	reply.Dirs = []string{filepath.Dir(target.UserHome)}
	set = ResolveWatchPaths(context.Background(), opts)
	if set.DirsErr == nil || !strings.Contains(set.DirsErr.Error(), "outside the target home") || set.OwnershipErr == nil {
		t.Fatalf("root ResolveWatchPaths accepted a watch dir outside the home: %+v", set)
	}
}

// requireCodexWatchFixture creates the Codex config and hook directory that
// WatchDirs and WatchOwnedFiles report for a codex target.
func requireCodexWatchFixture(t *testing.T, home string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw", "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestTargetWorkerSubprocessResolvesWatchPaths(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	target := currentTestTarget(t)
	requireCodexWatchFixture(t, target.UserHome)
	opts := codexInstallOptions(target.UserHome, target.UID, target.GID)
	opts.AgentVersion = ""
	// The worker reads the user's agent discovery cache for the version; a
	// FIFO there must not hold it up.
	if err := syscall.Mkfifo(filepath.Join(target.UserHome, ".defenseclaw", "agent_discovery.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantDirs, err := WatchDirs(opts)
	if err != nil {
		t.Fatal(err)
	}
	wantOwnership, err := WatchOwnedFiles(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	set, err := resolveWatchPathsThroughTargetWorker(ctx, opts)
	if err != nil {
		t.Fatalf("worker watch paths: %v", err)
	}
	if set.DirsErr != nil || set.OwnershipErr != nil || !slices.Equal(set.Dirs, wantDirs) ||
		!reflect.DeepEqual(set.Ownership, wantOwnership) {
		t.Fatalf("worker watch paths = %+v\nwant dirs %v ownership %+v", set, wantDirs, wantOwnership)
	}
}

func TestRootGuardianResolvesWatchPathsInWorkerDespiteFIFOCache(t *testing.T) {
	f := newRootWorkerFixture(t)
	f.mkdirTarget(t, filepath.Join(f.home, ".defenseclaw"))
	f.mkdirTarget(t, f.hookDir)
	cache := filepath.Join(f.home, ".defenseclaw", "agent_discovery.json")
	if err := syscall.Mkfifo(cache, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(cache, f.uid, f.gid); err != nil {
		t.Fatal(err)
	}
	opts := codexInstallOptions(f.home, f.uid, f.gid)
	opts.AgentVersion = ""
	if _, err := WatchDirs(opts); !errors.Is(err, errRootTargetPathOperation) {
		t.Fatalf("WatchDirs in the root guardian = %v, want refusal", err)
	}
	done := make(chan WatchPathSet, 1)
	go func() { done <- ResolveWatchPaths(context.Background(), opts) }()
	var set WatchPathSet
	select {
	case set = <-done:
	case <-time.After(30 * time.Second):
		if writer, err := os.OpenFile(cache, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = writer.Close()
		}
		<-done
		t.Fatal("root ResolveWatchPaths blocked on a FIFO agent discovery cache")
	}
	if set.DirsErr != nil || set.OwnershipErr != nil {
		t.Fatalf("root ResolveWatchPaths = %+v", set)
	}
	for _, want := range []string{filepath.Dir(f.codexConfig), filepath.Join(f.home, ".defenseclaw"), f.hookDir} {
		if !slices.Contains(set.Dirs, want) {
			t.Fatalf("root watch dirs = %v, missing %s", set.Dirs, want)
		}
	}
	if !slices.Contains(set.Ownership.SharedWriter, f.codexConfig) {
		t.Fatalf("root owned shared-writer files = %v, missing %s", set.Ownership.SharedWriter, f.codexConfig)
	}
}

// A target user can stop or block their own worker until its deadline. In a
// reconcile pass that costs that user's targets one deadline, not one per
// worker, and never delays other users' workers.
func TestTargetWorkerPassSkipsOnlyTheStalledUserForThePass(t *testing.T) {
	calls := map[int]int{}
	original := targetWorkerRunner
	targetWorkerRunner = func(_ context.Context, target TargetCredentials, _ string, _ json.RawMessage) (json.RawMessage, error) {
		calls[target.UID]++
		switch target.UID {
		case 1001:
			return nil, fmt.Errorf("enterprise hooks: target worker for uid 1001 did not finish: %w", context.DeadlineExceeded)
		case 1002:
			return nil, errors.New("enterprise hooks: target worker for uid 1002 failed: exit status 1")
		}
		return json.RawMessage(`{}`), nil
	}
	t.Cleanup(func() { targetWorkerRunner = original })
	stalled := TargetCredentials{UserHome: "/home/stalled", UID: 1001, GID: 1001}
	failing := TargetCredentials{UserHome: "/home/failing", UID: 1002, GID: 1002}
	healthy := TargetCredentials{UserHome: "/home/healthy", UID: 1003, GID: 1003}

	pass := WithTargetWorkerPass(context.Background())
	var skipped error
	for i := 0; i < 3; i++ {
		_, err := runTargetWorker(pass, stalled, targetOperationVerify, nil)
		if i > 0 {
			skipped = err
		}
		if _, err := runTargetWorker(pass, failing, targetOperationVerify, nil); err == nil {
			t.Fatal("failing worker reported success")
		}
		if _, err := runTargetWorker(pass, healthy, targetOperationVerify, nil); err != nil {
			t.Fatalf("healthy worker: %v", err)
		}
	}
	if calls[1001] != 1 || calls[1002] != 3 || calls[1003] != 3 {
		t.Fatalf("worker calls = %v, want one for the stalled user and every call for the others", calls)
	}
	if skipped == nil || !strings.Contains(skipped.Error(), targetWorkerPassSkipMessage) {
		t.Fatalf("skipped worker error = %v", skipped)
	}

	// The next pass tries the user again; outside a pass every call runs.
	if _, err := runTargetWorker(WithTargetWorkerPass(context.Background()), stalled, targetOperationVerify, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("next pass = %v, want a new worker attempt", err)
	}
	for i := 0; i < 2; i++ {
		_, _ = runTargetWorker(context.Background(), stalled, targetOperationVerify, nil)
	}
	if calls[1001] != 4 {
		t.Fatalf("stalled user worker calls = %d, want 4", calls[1001])
	}
}

// In a reconcile pass a root guardian that saw a user's worker miss its
// deadline does not start more workers for that user: not the repair after
// the failed verification, and not the watch-path resolution.
func TestRootReconcilePassSkipsFurtherWorkersAfterADeadline(t *testing.T) {
	target := currentTestTarget(t)
	stubTargetProcessEUID(t, 0)
	opts := codexInstallOptions(target.UserHome, target.UID, target.GID)
	var operations []string
	original := targetWorkerRunner
	targetWorkerRunner = func(_ context.Context, _ TargetCredentials, operation string, _ json.RawMessage) (json.RawMessage, error) {
		operations = append(operations, operation)
		return nil, fmt.Errorf("enterprise hooks: target worker for uid %d did not finish: %w", target.UID, context.DeadlineExceeded)
	}
	t.Cleanup(func() { targetWorkerRunner = original })

	pass := WithTargetWorkerPass(context.Background())
	if _, err := Verify(pass, opts); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Verify = %v, want the worker deadline", err)
	}
	if _, err := Install(pass, opts); err == nil || !strings.Contains(err.Error(), targetWorkerPassSkipMessage) {
		t.Fatalf("Install after a stalled worker = %v, want an immediate skip", err)
	}
	if set := ResolveWatchPaths(pass, opts); set.DirsErr == nil || set.OwnershipErr == nil {
		t.Fatalf("ResolveWatchPaths after a stalled worker = %+v, want an immediate skip", set)
	}
	if !slices.Equal(operations, []string{targetOperationVerifyWithWatchPaths}) {
		t.Fatalf("worker operations = %v, want only the verification that stalled", operations)
	}
}

func TestTargetWorkerPassRecognizesARealWorkerDeadline(t *testing.T) {
	target := currentTestTarget(t)
	pass := WithTargetWorkerPass(context.Background())
	ctx, cancel := context.WithTimeout(pass, 300*time.Millisecond)
	defer cancel()
	if _, err := runTargetWorker(ctx, target, testTargetOperationSleep, json.RawMessage(`null`)); err == nil ||
		!strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("hung worker = %v, want a deadline failure", err)
	}
	if _, err := runTargetWorker(pass, target, testTargetOperationIdentity, json.RawMessage(`"x"`)); err == nil ||
		!strings.Contains(err.Error(), targetWorkerPassSkipMessage) {
		t.Fatalf("worker after a real deadline = %v, want an immediate skip", err)
	}
}

// Root counterpart of the deadline subprocess test: the guardian stops a
// dropped worker that does not finish, and the pass starts no further
// workers for that user.
func TestRootGuardianWorkerDeadlineSkipsThatUserForThePass(t *testing.T) {
	f := newRootWorkerFixture(t)
	target := TargetCredentials{UserHome: f.home, UID: f.uid, GID: f.gid}
	pass := WithTargetWorkerPass(context.Background())
	ctx, cancel := context.WithTimeout(pass, 300*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := RunTargetOperation(ctx, target, testTargetOperationSleep, nil, nil); err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("hung root worker = %v, want a deadline failure", err)
	}
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("hung root worker was stopped after %s", elapsed)
	}
	var identity testTargetIdentity
	if err := RunTargetOperation(pass, target, testTargetOperationIdentity, "root", &identity); err == nil ||
		!strings.Contains(err.Error(), targetWorkerPassSkipMessage) {
		t.Fatalf("root worker after a deadline = %v, want an immediate skip", err)
	}
	if err := RunTargetOperation(context.Background(), target, testTargetOperationIdentity, "root", &identity); err != nil || identity.UID != f.uid {
		t.Fatalf("root worker outside the pass = %+v, %v", identity, err)
	}
}

const targetWorkerPassSkipMessage = "used up their time in this reconcile pass"

func stubTargetWorkerPassBudget(t *testing.T, budget time.Duration) {
	t.Helper()
	previous := targetWorkerPassBudget
	targetWorkerPassBudget = budget
	t.Cleanup(func() { targetWorkerPassBudget = previous })
}

// A user who stops each of their workers and resumes it just before its
// deadline never makes one miss it. The user's workers still share one
// budget per pass: each runs only for what is left of it, and none starts
// once it is used up. Other users keep their own budgets.
func TestTargetWorkerPassSharesOneBudgetAcrossAUsersWorkers(t *testing.T) {
	const budget = time.Second
	const pause = 700 * time.Millisecond
	stubTargetWorkerPassBudget(t, budget)
	var mu sync.Mutex
	calls := map[int]int{}
	left := map[int][]time.Duration{}
	original := targetWorkerRunner
	targetWorkerRunner = func(ctx context.Context, target TargetCredentials, _ string, _ json.RawMessage) (json.RawMessage, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, errors.New("worker has no deadline")
		}
		mu.Lock()
		calls[target.UID]++
		left[target.UID] = append(left[target.UID], time.Until(deadline))
		mu.Unlock()
		if target.UID != 1001 {
			return json.RawMessage(`{}`), nil
		}
		select {
		case <-time.After(pause):
			return json.RawMessage(`{}`), nil
		case <-ctx.Done():
			return nil, fmt.Errorf("enterprise hooks: target worker for uid 1001 did not finish: %w", ctx.Err())
		}
	}
	t.Cleanup(func() { targetWorkerRunner = original })
	pausing := TargetCredentials{UserHome: "/home/pausing", UID: 1001, GID: 1001}
	healthy := TargetCredentials{UserHome: "/home/healthy", UID: 1003, GID: 1003}

	pass := WithTargetWorkerPass(context.Background())
	started := time.Now()
	var errs []error
	for i := 0; i < 3; i++ {
		_, err := runTargetWorker(pass, pausing, targetOperationVerify, nil)
		errs = append(errs, err)
		if _, err := runTargetWorker(pass, healthy, targetOperationVerify, nil); err != nil {
			t.Fatalf("healthy worker %d: %v", i, err)
		}
	}
	elapsed := time.Since(started)
	if errs[0] != nil || !errors.Is(errs[1], context.DeadlineExceeded) ||
		errs[2] == nil || !strings.Contains(errs[2].Error(), targetWorkerPassSkipMessage) {
		t.Fatalf("pausing user's workers = %v, want one in time, one stopped at the budget, one skipped", errs)
	}
	if calls[1001] != 2 || calls[1003] != 3 {
		t.Fatalf("worker calls = %v, want 2 for the pausing user and 3 for the other", calls)
	}
	if second := left[1001][1]; second > budget-pause {
		t.Fatalf("second worker had %s, want at most the %s left of the budget", second, budget-pause)
	}
	for i, got := range left[1003] {
		if got < budget-100*time.Millisecond {
			t.Fatalf("other user's worker %d had %s, want its own full budget", i, got)
		}
	}
	// Three workers that each pause for 700ms would take 2.1s.
	if elapsed > budget+700*time.Millisecond {
		t.Fatalf("pass took %s, want about the %s budget", elapsed, budget)
	}
}

// The same with real worker processes.
func TestTargetWorkerSubprocessPassBudgetStopsAPausingUser(t *testing.T) {
	target := currentTestTarget(t)
	stubTargetWorkerPassBudget(t, 1500*time.Millisecond)
	pass := WithTargetWorkerPass(context.Background())
	started := time.Now()
	var errs []error
	for i := 0; i < 3; i++ {
		_, err := runTargetWorker(pass, target, testTargetOperationPause, json.RawMessage(`1000`))
		errs = append(errs, err)
	}
	elapsed := time.Since(started)
	if errs[0] != nil || errs[1] == nil || !strings.Contains(errs[1].Error(), "did not finish") ||
		errs[2] == nil || !strings.Contains(errs[2].Error(), targetWorkerPassSkipMessage) {
		t.Fatalf("pausing workers = %v, want one in time, one stopped at the budget, one skipped", errs)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("pass took %s", elapsed)
	}
}

// In a reconcile pass the Install or Verify worker also reports the
// target's watch paths, so ResolveWatchPaths starts no worker of its own,
// and the paths come from the last worker that ran for those options.
func TestRootReconcilePassTakesWatchPathsFromTheInstallOrVerifyWorker(t *testing.T) {
	target := currentTestTarget(t)
	stubTargetProcessEUID(t, 0)
	opts := codexInstallOptions(target.UserHome, target.UID, target.GID)
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")
	result := InstallResult{Connector: "codex", UserHome: target.UserHome, DataDir: dataDir}
	answers := map[string]targetInstallWithWatchPathsResult{
		targetOperationVerifyWithWatchPaths: {
			Error: "enterprise hooks: specific verification failure",
			Watch: targetWatchPathsResult{Dirs: []string{filepath.Join(target.UserHome, ".codex")}},
		},
		targetOperationInstallWithWatchPaths: {
			Result: &result,
			Watch: targetWatchPathsResult{
				Dirs:         []string{filepath.Join(target.UserHome, ".codex"), dataDir},
				SharedWriter: []string{filepath.Join(target.UserHome, ".codex", "config.toml")},
			},
		},
	}
	var operations []string
	original := targetWorkerRunner
	targetWorkerRunner = func(_ context.Context, _ TargetCredentials, operation string, _ json.RawMessage) (json.RawMessage, error) {
		operations = append(operations, operation)
		answer, ok := answers[operation]
		if !ok {
			return nil, fmt.Errorf("unexpected worker operation %s", operation)
		}
		return json.Marshal(answer)
	}
	t.Cleanup(func() { targetWorkerRunner = original })

	pass := WithTargetWorkerPass(context.Background())
	if _, err := Verify(pass, opts); err == nil || err.Error() != "enterprise hooks: specific verification failure" {
		t.Fatalf("Verify = %v, want the worker's own failure", err)
	}
	set := ResolveWatchPaths(pass, opts)
	if set.DirsErr != nil || !slices.Equal(set.Dirs, answers[targetOperationVerifyWithWatchPaths].Watch.Dirs) {
		t.Fatalf("watch paths after a failed verification = %+v", set)
	}
	if got, err := Install(pass, opts); err != nil || got.UserHome != target.UserHome {
		t.Fatalf("Install = %+v, %v", got, err)
	}
	set = ResolveWatchPaths(pass, opts)
	install := answers[targetOperationInstallWithWatchPaths].Watch
	if set.DirsErr != nil || set.OwnershipErr != nil || !slices.Equal(set.Dirs, install.Dirs) ||
		!slices.Equal(set.Ownership.SharedWriter, install.SharedWriter) {
		t.Fatalf("watch paths after the repair = %+v, want %+v", set, install)
	}
	if want := []string{targetOperationVerifyWithWatchPaths, targetOperationInstallWithWatchPaths}; !slices.Equal(operations, want) {
		t.Fatalf("worker operations = %v, want %v", operations, want)
	}

	// Other options are another request: that one needs its own worker.
	other := opts
	other.AgentVersion = "codex-cli 0.143.0"
	operations = nil
	if set := ResolveWatchPaths(pass, other); set.DirsErr == nil {
		t.Fatalf("watch paths for other options = %+v, want this stub's refusal", set)
	}
	if !slices.Equal(operations, []string{targetOperationWatchPaths}) {
		t.Fatalf("worker operations = %v, want one %s", operations, targetOperationWatchPaths)
	}

	// A watch directory outside the home fails both halves, and the result
	// still binds to the target.
	answers[targetOperationVerifyWithWatchPaths] = targetInstallWithWatchPathsResult{
		Result: &result,
		Watch:  targetWatchPathsResult{Dirs: []string{filepath.Dir(target.UserHome)}},
	}
	if _, err := Verify(pass, opts); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if set := ResolveWatchPaths(pass, opts); set.DirsErr == nil || !strings.Contains(set.DirsErr.Error(), "outside the target home") || set.OwnershipErr == nil {
		t.Fatalf("watch paths with a directory outside the home = %+v", set)
	}
	foreign := result
	foreign.UserHome = t.TempDir()
	answers[targetOperationVerifyWithWatchPaths] = targetInstallWithWatchPathsResult{Result: &foreign}
	if _, err := Verify(pass, opts); err == nil || !strings.Contains(err.Error(), "different target") {
		t.Fatalf("Verify accepted a result for another home: %v", err)
	}
}

func TestTargetWorkerSubprocessReportsWatchPathsWithInstallAndVerify(t *testing.T) {
	requireEnterpriseHookInstaller(t)
	target := currentTestTarget(t)
	requireCodexWatchFixture(t, target.UserHome)
	opts := codexInstallOptions(target.UserHome, target.UID, target.GID)
	opts.AllowMissingHookConfigRepair = true
	var operations []string
	original := targetWorkerRunner
	targetWorkerRunner = func(ctx context.Context, workerTarget TargetCredentials, operation string, payload json.RawMessage) (json.RawMessage, error) {
		operations = append(operations, operation)
		return spawnTargetWorker(ctx, workerTarget, operation, payload)
	}
	t.Cleanup(func() { targetWorkerRunner = original })

	pass := WithTargetWorkerPass(context.Background())
	if _, err := installThroughTargetWorker(pass, opts, targetOperationInstall); err != nil {
		t.Fatalf("worker Install: %v", err)
	}
	// The root path of ResolveWatchPaths; this test process is not root.
	set, err := resolveWatchPathsThroughTargetWorker(pass, opts)
	if err != nil {
		t.Fatal(err)
	}
	wantDirs, err := WatchDirs(opts)
	if err != nil {
		t.Fatal(err)
	}
	wantOwnership, err := WatchOwnedFiles(opts)
	if err != nil {
		t.Fatal(err)
	}
	if set.DirsErr != nil || set.OwnershipErr != nil || !slices.Equal(set.Dirs, wantDirs) ||
		!reflect.DeepEqual(set.Ownership, wantOwnership) {
		t.Fatalf("watch paths from the install worker = %+v\nwant dirs %v ownership %+v", set, wantDirs, wantOwnership)
	}
	if _, err := installThroughTargetWorker(pass, opts, targetOperationVerify); err != nil {
		t.Fatalf("worker Verify: %v", err)
	}
	if again, err := resolveWatchPathsThroughTargetWorker(pass, opts); err != nil || again.DirsErr != nil || !slices.Equal(again.Dirs, wantDirs) {
		t.Fatalf("watch paths from the verify worker = %+v, %v", again, err)
	}
	if want := []string{targetOperationInstallWithWatchPaths, targetOperationVerifyWithWatchPaths}; !slices.Equal(operations, want) {
		t.Fatalf("worker operations = %v, want %v", operations, want)
	}
}

// Root counterpart: a reconcile pass repairs a target and resolves its
// watch paths with one worker.
func TestRootGuardianReconcilePassRepairsAndResolvesWatchPathsInOneWorker(t *testing.T) {
	f := newRootWorkerFixture(t)
	if err := os.Chmod(f.codexConfig, 0o666); err != nil {
		t.Fatal(err)
	}
	opts := f.repairOptions()
	var operations []string
	original := targetWorkerRunner
	targetWorkerRunner = func(ctx context.Context, target TargetCredentials, operation string, payload json.RawMessage) (json.RawMessage, error) {
		operations = append(operations, operation)
		return spawnTargetWorker(ctx, target, operation, payload)
	}
	t.Cleanup(func() { targetWorkerRunner = original })
	pass := WithTargetWorkerPass(context.Background())
	if _, err := Install(pass, opts); err != nil {
		t.Fatalf("root Install in a pass: %v", err)
	}
	set := ResolveWatchPaths(pass, opts)
	if set.DirsErr != nil || set.OwnershipErr != nil {
		t.Fatalf("root watch paths = %+v", set)
	}
	for _, want := range []string{filepath.Dir(f.codexConfig), filepath.Join(f.home, ".defenseclaw"), f.hookDir} {
		if !slices.Contains(set.Dirs, want) {
			t.Fatalf("root watch dirs = %v, missing %s", set.Dirs, want)
		}
	}
	if !slices.Contains(set.Ownership.SharedWriter, f.codexConfig) {
		t.Fatalf("root shared-writer files = %v, missing %s", set.Ownership.SharedWriter, f.codexConfig)
	}
	if !slices.Equal(operations, []string{targetOperationInstallWithWatchPaths}) {
		t.Fatalf("worker operations = %v, want one %s", operations, targetOperationInstallWithWatchPaths)
	}
}
