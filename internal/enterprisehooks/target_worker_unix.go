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
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// A root guardian never touches a user's home with its own credentials and
// never changes its own credentials. Every target-user operation runs in a
// short-lived worker: the guardian re-executes its own image, the worker
// permanently becomes the target user (setgroups/setgid/setuid, so no saved
// root id remains) before it reads or writes any user path, and every
// mutation is then subject to the kernel's permission checks for that user.
// Because the worker starts as root and drops itself, it is never observable
// or debuggable by the target user while it holds any privilege, and after
// the drop the kernel marks it as having changed credentials.

const (
	// targetWorkerArg selects the worker entry point. It is deliberately not
	// a CLI command so cobra, config loading and native install-state
	// handling never run in the worker.
	targetWorkerArg = "__defenseclaw-enterprise-target-worker"

	targetWorkerProtocolVersion = 1
	targetWorkerRequestLimit    = 1 << 20
	targetWorkerResponseLimit   = 8 << 20
	targetWorkerStderrLimit     = 64 << 10
	targetWorkerTimeout         = 2 * time.Minute
	targetWorkerWaitDelay       = 5 * time.Second

	targetOperationInstall    = "enterprise-hooks.install"
	targetOperationVerify     = "enterprise-hooks.verify"
	targetOperationWatchPaths = "enterprise-hooks.watch-paths"
	// Install and Verify that also report the target's watch paths, for a
	// reconcile pass (see WithTargetWorkerPass). A guardian that predates
	// them sends only the plain operations, whose answers are unchanged.
	targetOperationInstallWithWatchPaths = "enterprise-hooks.install-with-watch-paths"
	targetOperationVerifyWithWatchPaths  = "enterprise-hooks.verify-with-watch-paths"

	targetWorkerExitProtocol = 2
	targetWorkerExitIdentity = 3
	targetWorkerExitDeadline = 4
)

// targetWorkerPassthroughEnv lists administrator-controlled settings the
// in-worker installer reads. Nothing else from the guardian's environment
// reaches the worker.
var targetWorkerPassthroughEnv = []string{
	"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT",
	"DEFENSECLAW_CODEX_LOOPBACK_TRUST",
	"DEFENSECLAW_DEPLOYMENT_MODE",
	"DEFENSECLAW_HOME",
	"DEFENSECLAW_TRUSTED_BIN_PREFIXES",
	"DEFENSECLAW_UNIX_SERVICE_ACCOUNT",
}

var (
	// targetProcessEUID is the effective uid used for privilege routing.
	targetProcessEUID = os.Geteuid
	// targetWorkerRunner runs one operation in a worker process.
	targetWorkerRunner = spawnTargetWorker
	// targetWorkerExecutable returns the worker image path and argv[0].
	targetWorkerExecutable = defaultTargetWorkerExecutable
	// targetWorkerLog receives the worker's bounded diagnostics.
	targetWorkerLog io.Writer = os.Stderr
	// targetWorkerActive is set inside a worker process.
	targetWorkerActive atomic.Bool
	// targetWorkerEntrypointReady is set once this executable has checked
	// for the worker argument, which proves re-executing it reaches the
	// worker rather than an ordinary command line.
	targetWorkerEntrypointReady atomic.Bool
)

var (
	errTargetWorkerRecursion = errors.New("enterprise hooks: target worker is still privileged; refusing to start another worker")
	errTargetWorkerNoEntry   = errors.New(
		"enterprise hooks: this executable does not host the per-target worker; call RunTargetWorkerIfRequested at startup",
	)
)

type targetWorkerRequest struct {
	Version   int             `json:"version"`
	Operation string          `json:"operation"`
	UID       int             `json:"uid"`
	GID       int             `json:"gid"`
	Home      string          `json:"home"`
	Payload   json.RawMessage `json:"payload"`
	// BinaryVersion is the guardian's release version. The worker exits
	// before CLI initialization records it, and operations stamp it into
	// the files they write (the hook contract lock's defenseclaw_version).
	BinaryVersion string `json:"binary_version,omitempty"`
}

type targetWorkerResponse struct {
	Version int             `json:"version"`
	OK      bool            `json:"ok"`
	Error   string          `json:"error,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// targetInstallRequest carries InstallOptions across the worker boundary.
// Registry is rebuilt in the worker from the built-in connectors and
// OwnerSID is Windows-only.
type targetInstallRequest struct {
	ConnectorName                      string `json:"connector"`
	UserHome                           string `json:"user_home"`
	OwnerUID                           int    `json:"owner_uid"`
	OwnerGID                           int    `json:"owner_gid"`
	DataDir                            string `json:"data_dir,omitempty"`
	APIAddr                            string `json:"api_addr,omitempty"`
	ProxyAddr                          string `json:"proxy_addr,omitempty"`
	APIToken                           string `json:"api_token,omitempty"`
	OTLPPathToken                      string `json:"otlp_path_token,omitempty"`
	MasterKey                          string `json:"master_key,omitempty"`
	HookFailMode                       string `json:"hook_fail_mode,omitempty"`
	GuardrailMode                      string `json:"guardrail_mode,omitempty"`
	HILTEnabled                        bool   `json:"hilt_enabled,omitempty"`
	AgentVersion                       string `json:"agent_version,omitempty"`
	HookContractID                     string `json:"hook_contract_id,omitempty"`
	RecoveryHookContractLockUpdatedAt  string `json:"recovery_hook_contract_lock_updated_at,omitempty"`
	RecoveryHookContractEntryUpdatedAt string `json:"recovery_hook_contract_entry_updated_at,omitempty"`
	WorkspaceDir                       string `json:"workspace_dir,omitempty"`
	AllowMissingHookConfigRepair       bool   `json:"allow_missing_hook_config_repair,omitempty"`
}

func newTargetInstallRequest(opts InstallOptions, home string, uid, gid int) targetInstallRequest {
	return targetInstallRequest{
		ConnectorName:                      opts.ConnectorName,
		UserHome:                           home,
		OwnerUID:                           uid,
		OwnerGID:                           gid,
		DataDir:                            opts.DataDir,
		APIAddr:                            opts.APIAddr,
		ProxyAddr:                          opts.ProxyAddr,
		APIToken:                           opts.APIToken,
		OTLPPathToken:                      opts.OTLPPathToken,
		MasterKey:                          opts.MasterKey,
		HookFailMode:                       opts.HookFailMode,
		GuardrailMode:                      opts.GuardrailMode,
		HILTEnabled:                        opts.HILTEnabled,
		AgentVersion:                       opts.AgentVersion,
		HookContractID:                     opts.HookContractID,
		RecoveryHookContractLockUpdatedAt:  opts.RecoveryHookContractLockUpdatedAt,
		RecoveryHookContractEntryUpdatedAt: opts.RecoveryHookContractEntryUpdatedAt,
		WorkspaceDir:                       opts.WorkspaceDir,
		AllowMissingHookConfigRepair:       opts.AllowMissingHookConfigRepair,
	}
}

func (r targetInstallRequest) installOptions() InstallOptions {
	return InstallOptions{
		ConnectorName:                      r.ConnectorName,
		UserHome:                           r.UserHome,
		OwnerUID:                           r.OwnerUID,
		OwnerGID:                           r.OwnerGID,
		DataDir:                            r.DataDir,
		APIAddr:                            r.APIAddr,
		ProxyAddr:                          r.ProxyAddr,
		APIToken:                           r.APIToken,
		OTLPPathToken:                      r.OTLPPathToken,
		MasterKey:                          r.MasterKey,
		HookFailMode:                       r.HookFailMode,
		GuardrailMode:                      r.GuardrailMode,
		HILTEnabled:                        r.HILTEnabled,
		AgentVersion:                       r.AgentVersion,
		HookContractID:                     r.HookContractID,
		RecoveryHookContractLockUpdatedAt:  r.RecoveryHookContractLockUpdatedAt,
		RecoveryHookContractEntryUpdatedAt: r.RecoveryHookContractEntryUpdatedAt,
		WorkspaceDir:                       r.WorkspaceDir,
		Registry:                           connector.NewDefaultRegistry(),
		AllowMissingHookConfigRepair:       r.AllowMissingHookConfigRepair,
	}
}

func init() {
	RegisterTargetOperation(targetOperationInstall, func(ctx context.Context, target TargetCredentials, payload json.RawMessage) (any, error) {
		opts, err := decodeTargetInstallRequest(target, payload)
		if err != nil {
			return nil, err
		}
		result, err := Install(ctx, opts)
		if err != nil {
			return nil, err
		}
		return result, nil
	})
	RegisterTargetOperation(targetOperationVerify, func(ctx context.Context, target TargetCredentials, payload json.RawMessage) (any, error) {
		opts, err := decodeTargetInstallRequest(target, payload)
		if err != nil {
			return nil, err
		}
		result, err := Verify(ctx, opts)
		if err != nil {
			return nil, err
		}
		return result, nil
	})
	RegisterTargetOperation(targetOperationWatchPaths, func(_ context.Context, target TargetCredentials, payload json.RawMessage) (any, error) {
		opts, err := decodeTargetInstallRequest(target, payload)
		if err != nil {
			return nil, err
		}
		return resolveTargetWatchPaths(opts), nil
	})
	registerTargetInstallWithWatchPaths(targetOperationInstallWithWatchPaths, Install)
	registerTargetInstallWithWatchPaths(targetOperationVerifyWithWatchPaths, Verify)
}

// targetInstallWithWatchPathsResult answers an Install or Verify that also
// resolves the target's watch paths after the operation, whether or not it
// succeeded. Error is the operation's own failure.
type targetInstallWithWatchPathsResult struct {
	Result *InstallResult         `json:"result,omitempty"`
	Error  string                 `json:"error,omitempty"`
	Watch  targetWatchPathsResult `json:"watch"`
}

func registerTargetInstallWithWatchPaths(name string, run func(context.Context, InstallOptions) (InstallResult, error)) {
	RegisterTargetOperation(name, func(ctx context.Context, target TargetCredentials, payload json.RawMessage) (any, error) {
		opts, err := decodeTargetInstallRequest(target, payload)
		if err != nil {
			return nil, err
		}
		var answer targetInstallWithWatchPathsResult
		result, err := run(ctx, opts)
		if err != nil {
			answer.Error = err.Error()
			if answer.Error == "" {
				answer.Error = "enterprise hooks: target operation failed without a reason"
			}
		} else {
			answer.Result = &result
		}
		answer.Watch = resolveTargetWatchPaths(opts)
		return answer, nil
	})
}

// targetWatchPathsResult carries WatchDirs and WatchOwnedFiles back from
// the worker; each keeps its own error, as the in-process calls do.
type targetWatchPathsResult struct {
	Dirs            []string `json:"dirs,omitempty"`
	DirsError       string   `json:"dirs_error,omitempty"`
	ExclusiveWriter []string `json:"exclusive_writer,omitempty"`
	SharedWriter    []string `json:"shared_writer,omitempty"`
	OwnershipError  string   `json:"ownership_error,omitempty"`
}

func resolveTargetWatchPaths(opts InstallOptions) targetWatchPathsResult {
	var result targetWatchPathsResult
	if dirs, err := WatchDirs(opts); err != nil {
		result.DirsError = err.Error()
	} else {
		result.Dirs = dirs
	}
	if ownership, err := WatchOwnedFiles(opts); err != nil {
		result.OwnershipError = err.Error()
	} else {
		result.ExclusiveWriter = ownership.ExclusiveWriter
		result.SharedWriter = ownership.SharedWriter
	}
	return result
}

func decodeTargetInstallRequest(target TargetCredentials, payload json.RawMessage) (InstallOptions, error) {
	var request targetInstallRequest
	if err := decodeTargetOperationJSON(payload, &request); err != nil {
		return InstallOptions{}, fmt.Errorf("enterprise hooks: decode target install request: %w", err)
	}
	if filepath.Clean(request.UserHome) != filepath.Clean(target.UserHome) ||
		request.OwnerUID != target.UID || request.OwnerGID != target.GID {
		return InstallOptions{}, fmt.Errorf("enterprise hooks: target install request does not match the worker identity")
	}
	return request.installOptions(), nil
}

// targetWorkerInstallCall is a root guardian's request for one target's
// Install-shaped worker operation, with the identity it resolved.
type targetWorkerInstallCall struct {
	target    TargetCredentials
	connector string
	dataDir   string
	payload   json.RawMessage
}

// prepareTargetWorkerInstallCall resolves the target's identity (read-only)
// and encodes opts for the worker, which does every validation and repair.
func prepareTargetWorkerInstallCall(opts InstallOptions) (targetWorkerInstallCall, error) {
	if targetWorkerActive.Load() {
		return targetWorkerInstallCall{}, errTargetWorkerRecursion
	}
	home, err := validateUserHome(opts.UserHome)
	if err != nil {
		return targetWorkerInstallCall{}, err
	}
	uid, gid, err := resolveOwner(home, opts.OwnerUID, opts.OwnerGID)
	if err != nil {
		return targetWorkerInstallCall{}, err
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if name == "" {
		return targetWorkerInstallCall{}, fmt.Errorf("enterprise hooks: connector is required")
	}
	if opts.Registry != nil {
		conn, ok := opts.Registry.Get(name)
		if !ok {
			return targetWorkerInstallCall{}, fmt.Errorf("enterprise hooks: unknown connector %q", name)
		}
		if !connector.IsKnownBuiltinConnector(conn.Name()) {
			return targetWorkerInstallCall{}, fmt.Errorf(
				"enterprise hooks: connector %q is not built in; a root guardian runs only built-in connectors in the per-target worker",
				name,
			)
		}
	}
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(home, ".defenseclaw")
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return targetWorkerInstallCall{}, fmt.Errorf("enterprise hooks: resolve data dir: %w", err)
	}
	payload, err := json.Marshal(newTargetInstallRequest(opts, home, uid, gid))
	if err != nil {
		return targetWorkerInstallCall{}, fmt.Errorf("enterprise hooks: encode target install request: %w", err)
	}
	return targetWorkerInstallCall{
		target:    TargetCredentials{UserHome: home, UID: uid, GID: gid},
		connector: name,
		dataDir:   dataDir,
		payload:   payload,
	}, nil
}

// installThroughTargetWorker is the root path of Install and Verify on Unix.
// The guardian only resolves the target's identity (read-only) and then
// hands the whole operation, including every validation and repair, to a
// worker running as that user. In a reconcile pass the same worker also
// reports the target's watch paths, which the pass keeps for
// ResolveWatchPaths.
func installThroughTargetWorker(ctx context.Context, opts InstallOptions, operation string) (InstallResult, error) {
	call, err := prepareTargetWorkerInstallCall(opts)
	if err != nil {
		return InstallResult{}, err
	}
	pass := targetWorkerPassFrom(ctx)
	withWatchPaths := map[string]string{
		targetOperationInstall: targetOperationInstallWithWatchPaths,
		targetOperationVerify:  targetOperationVerifyWithWatchPaths,
	}[operation]
	if pass == nil || withWatchPaths == "" {
		raw, err := runTargetWorker(ctx, call.target, operation, call.payload)
		if err != nil {
			return InstallResult{}, err
		}
		var result InstallResult
		if err := decodeTargetOperationJSON(raw, &result); err != nil {
			return InstallResult{}, fmt.Errorf("enterprise hooks: decode target worker result: %w", err)
		}
		return call.bindResult(result)
	}
	raw, err := runTargetWorker(ctx, call.target, withWatchPaths, call.payload)
	if err != nil {
		return InstallResult{}, err
	}
	var answer targetInstallWithWatchPathsResult
	if err := decodeTargetOperationJSON(raw, &answer); err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: decode target worker result: %w", err)
	}
	pass.storeWatchPaths(call.payload, call.watchPathSet(answer.Watch))
	if answer.Error != "" {
		// Keep the operation's own message, as spawnTargetWorker does.
		return InstallResult{}, errors.New(answer.Error)
	}
	if answer.Result == nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: target worker returned no result")
	}
	return call.bindResult(*answer.Result)
}

// bindResult accepts a worker's result only for the target the guardian
// asked about: the worker runs as the target user.
func (call targetWorkerInstallCall) bindResult(result InstallResult) (InstallResult, error) {
	if result.Connector != call.connector || filepath.Clean(result.UserHome) != call.target.UserHome ||
		filepath.Clean(result.DataDir) != call.dataDir {
		return InstallResult{}, fmt.Errorf("enterprise hooks: target worker returned a result for a different target")
	}
	return result, nil
}

// watchPathSet converts a worker's watch paths. The guardian watches these
// directories with its own credentials, so it accepts only what WatchDirs
// can return: clean absolute paths inside the target home; otherwise both
// halves fail. Owned files are watched only inside those directories.
func (call targetWorkerInstallCall) watchPathSet(result targetWatchPathsResult) WatchPathSet {
	for _, dir := range result.Dirs {
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || !pathInside(call.target.UserHome, dir) {
			err := fmt.Errorf("enterprise hooks: target worker returned watch directory %q outside the target home", dir)
			return WatchPathSet{DirsErr: err, OwnershipErr: err}
		}
	}
	set := WatchPathSet{
		Dirs:      result.Dirs,
		Ownership: WatchOwnership{ExclusiveWriter: result.ExclusiveWriter, SharedWriter: result.SharedWriter},
	}
	if result.DirsError != "" {
		set.DirsErr = errors.New(result.DirsError)
	}
	if result.OwnershipError != "" {
		set.OwnershipErr = errors.New(result.OwnershipError)
	}
	return set
}

// resolveWatchPathsThroughTargetWorker is the root path of ResolveWatchPaths
// on Unix: the worker, running as the target user, computes WatchDirs and
// WatchOwnedFiles. In a reconcile pass it takes them from the Install or
// Verify worker that already ran for the same request.
func resolveWatchPathsThroughTargetWorker(ctx context.Context, opts InstallOptions) (WatchPathSet, error) {
	call, err := prepareTargetWorkerInstallCall(opts)
	if err != nil {
		return WatchPathSet{}, err
	}
	if pass := targetWorkerPassFrom(ctx); pass != nil {
		if set, ok := pass.watchPaths(call.payload); ok {
			return set, nil
		}
	}
	raw, err := runTargetWorker(ctx, call.target, targetOperationWatchPaths, call.payload)
	if err != nil {
		return WatchPathSet{}, err
	}
	var result targetWatchPathsResult
	if err := decodeTargetOperationJSON(raw, &result); err != nil {
		return WatchPathSet{}, fmt.Errorf("enterprise hooks: decode target worker watch paths: %w", err)
	}
	return call.watchPathSet(result), nil
}

// runTargetWorker runs one operation in a worker. In a reconcile pass (see
// WithTargetWorkerPass) the worker runs only for what is left of its user's
// budget, and does not start once that is used up.
func runTargetWorker(ctx context.Context, target TargetCredentials, operation string, payload json.RawMessage) (json.RawMessage, error) {
	pass := targetWorkerPassFrom(ctx)
	if pass == nil {
		return targetWorkerRunner(ctx, target, operation, payload)
	}
	left, ok := pass.remaining(target.UID)
	if !ok {
		return nil, fmt.Errorf(
			"enterprise hooks: skipping the target worker for uid %d: this user's workers used up their time in this reconcile pass",
			target.UID,
		)
	}
	workerCtx, cancel := context.WithTimeout(ctx, left)
	defer cancel()
	started := time.Now()
	raw, err := targetWorkerRunner(workerCtx, target, operation, payload)
	pass.charge(target.UID, time.Since(started), err != nil && errors.Is(err, context.DeadlineExceeded))
	return raw, err
}

// runTargetOperation validates the target and runs op with its credentials.
func runTargetOperation(
	ctx context.Context,
	target TargetCredentials,
	name string,
	op TargetOperation,
	payload json.RawMessage,
) (json.RawMessage, error) {
	home, err := validateUserHome(target.UserHome)
	if err != nil {
		return nil, err
	}
	uid, gid, err := resolveOwner(home, target.UID, target.GID)
	if err != nil {
		return nil, err
	}
	target = TargetCredentials{UserHome: home, UID: uid, GID: gid}
	if targetProcessEUID() == 0 {
		if targetWorkerActive.Load() {
			return nil, errTargetWorkerRecursion
		}
		return runTargetWorker(ctx, target, name, payload)
	}
	var result json.RawMessage
	err = withOwnerCredentials(uid, gid, func() error {
		var opErr error
		result, opErr = invokeTargetOperation(ctx, target, op, payload)
		return opErr
	})
	return result, err
}

// spawnTargetWorker runs one operation in a fresh worker process and returns
// its JSON result.
func spawnTargetWorker(ctx context.Context, target TargetCredentials, operation string, payload json.RawMessage) (json.RawMessage, error) {
	if target.UID <= 0 || target.GID < 0 {
		return nil, fmt.Errorf("enterprise hooks: refusing a target worker for uid %d gid %d", target.UID, target.GID)
	}
	if euid := targetProcessEUID(); euid != 0 && euid != target.UID {
		return nil, fmt.Errorf("enterprise hooks: an unprivileged process (euid %d) can run a target worker only for itself", euid)
	}
	if !targetWorkerEntrypointReady.Load() {
		return nil, errTargetWorkerNoEntry
	}
	request, err := json.Marshal(targetWorkerRequest{
		Version:   targetWorkerProtocolVersion,
		Operation: operation,
		UID:       target.UID,
		GID:       target.GID,
		Home:      target.UserHome,
		Payload:   payload,

		BinaryVersion: version.Current().BinaryVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: encode target worker request: %w", err)
	}
	executable, argv0, err := targetWorkerExecutable()
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, targetWorkerTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, executable, targetWorkerArg)
	if argv0 != "" {
		cmd.Args[0] = argv0
	}
	cmd.Dir = "/"
	cmd.Env = targetWorkerEnvironment(target)
	cmd.Stdin = bytes.NewReader(request)
	stdout := &boundedTargetWorkerBuffer{limit: targetWorkerResponseLimit}
	stderr := &boundedTargetWorkerBuffer{limit: targetWorkerStderrLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = targetWorkerSysProcAttr()
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// The worker leads its own session; stop any helper it started too.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = targetWorkerWaitDelay
	// Linux delivers the worker's parent-death signal when the forking
	// thread exits; keep that thread alive until the worker is reaped.
	runtime.LockOSThread()
	runErr := cmd.Run()
	runtime.UnlockOSThread()
	forwardTargetWorkerStderr(stderr)
	if ctx.Err() != nil {
		return nil, fmt.Errorf("enterprise hooks: target worker for uid %d did not finish: %w", target.UID, ctx.Err())
	}
	if stdout.exceeded {
		return nil, fmt.Errorf("enterprise hooks: target worker for uid %d returned an oversized response", target.UID)
	}
	var response targetWorkerResponse
	if err := decodeTargetOperationJSON(stdout.buf.Bytes(), &response); err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("enterprise hooks: target worker for uid %d failed: %w", target.UID, runErr)
		}
		return nil, fmt.Errorf("enterprise hooks: target worker for uid %d returned an invalid response: %w", target.UID, err)
	}
	if response.Version != targetWorkerProtocolVersion {
		return nil, fmt.Errorf("enterprise hooks: target worker for uid %d speaks protocol %d, want %d", target.UID, response.Version, targetWorkerProtocolVersion)
	}
	if !response.OK {
		if strings.TrimSpace(response.Error) == "" {
			return nil, fmt.Errorf("enterprise hooks: target worker for uid %d failed without a reason", target.UID)
		}
		// Keep the operation's own message so callers and logs see the
		// same diagnostics as an in-process install.
		return nil, errors.New(response.Error)
	}
	if runErr != nil {
		return nil, fmt.Errorf("enterprise hooks: target worker for uid %d failed: %w", target.UID, runErr)
	}
	return response.Payload, nil
}

func targetWorkerEnvironment(target TargetCredentials) []string {
	path := strings.TrimSpace(os.Getenv("PATH"))
	if path == "" {
		path = "/usr/bin:/bin:/usr/sbin:/sbin"
	}
	env := []string{"HOME=" + target.UserHome, "PATH=" + path}
	if account, err := user.LookupId(strconv.Itoa(target.UID)); err == nil && account.Username != "" {
		env = append(env, "USER="+account.Username, "LOGNAME="+account.Username)
	}
	for _, name := range targetWorkerPassthroughEnv {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

type boundedTargetWorkerBuffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedTargetWorkerBuffer) Write(p []byte) (int, error) {
	if remaining := b.limit - b.buf.Len(); len(p) > remaining {
		b.exceeded = true
		if remaining > 0 {
			b.buf.Write(p[:remaining])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func forwardTargetWorkerStderr(stderr *boundedTargetWorkerBuffer) {
	if targetWorkerLog == nil || stderr.buf.Len() == 0 {
		return
	}
	_, _ = targetWorkerLog.Write(stderr.buf.Bytes())
	if stderr.exceeded {
		_, _ = io.WriteString(targetWorkerLog, "\nenterprise hooks: target worker diagnostics truncated\n")
	}
}

// RunTargetWorkerIfRequested runs the per-target worker when this process
// was started as one. Executables that can run Install or
// RunTargetOperation as root must call it first in main, before any other
// initialization; it reports whether the process was a worker and the exit
// code to use.
func RunTargetWorkerIfRequested() (bool, int) {
	targetWorkerEntrypointReady.Store(true)
	if len(os.Args) != 2 || os.Args[1] != targetWorkerArg {
		return false, 0
	}
	response := os.Stdout
	// Operations and the helpers they start must not write into the
	// response stream; route incidental output to diagnostics.
	os.Stdout = os.Stderr
	return true, runTargetWorkerMain(os.Stdin, response, os.Stderr)
}

func runTargetWorkerMain(stdin io.Reader, stdout, stderr io.Writer) int {
	respond := func(response targetWorkerResponse, code int) int {
		response.Version = targetWorkerProtocolVersion
		if err := json.NewEncoder(stdout).Encode(response); err != nil {
			fmt.Fprintf(stderr, "enterprise hooks: target worker: write response: %v\n", err)
			if code == 0 {
				code = targetWorkerExitProtocol
			}
		}
		return code
	}
	fail := func(code int, format string, args ...any) int {
		return respond(targetWorkerResponse{Error: fmt.Sprintf(format, args...)}, code)
	}
	parentPID := os.Getppid()
	data, err := io.ReadAll(io.LimitReader(stdin, targetWorkerRequestLimit+1))
	if err != nil || len(data) > targetWorkerRequestLimit {
		return fail(targetWorkerExitProtocol, "enterprise hooks: target worker request is unreadable or too large")
	}
	var request targetWorkerRequest
	if err := decodeTargetOperationJSON(data, &request); err != nil {
		return fail(targetWorkerExitProtocol, "enterprise hooks: target worker request is invalid: %v", err)
	}
	if request.Version != targetWorkerProtocolVersion {
		return fail(targetWorkerExitProtocol, "enterprise hooks: target worker protocol %d is not supported", request.Version)
	}
	home := filepath.Clean(strings.TrimSpace(request.Home))
	if request.UID <= 0 || request.GID < 0 || !filepath.IsAbs(home) || home == string(filepath.Separator) || home != request.Home {
		return fail(targetWorkerExitProtocol, "enterprise hooks: target worker refuses uid %d gid %d home %q", request.UID, request.GID, request.Home)
	}
	op, ok := lookupTargetOperation(request.Operation)
	if !ok {
		return fail(targetWorkerExitProtocol, "enterprise hooks: unknown target operation %q", request.Operation)
	}
	// Become the target before anything reads or writes a user path.
	if err := dropToTargetCredentials(request.UID, request.GID); err != nil {
		return fail(targetWorkerExitIdentity, "enterprise hooks: target worker could not become uid %d gid %d: %v", request.UID, request.GID, err)
	}
	if err := hardenTargetWorkerProcess(parentPID); err != nil {
		return fail(targetWorkerExitIdentity, "enterprise hooks: target worker hardening failed: %v", err)
	}
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	syscall.Umask(0o077)
	if binaryVersion := strings.TrimSpace(request.BinaryVersion); binaryVersion != "" {
		version.SetBinaryVersion(binaryVersion)
	}
	targetWorkerActive.Store(true)
	// The guardian kills the worker's process group at its deadline. macOS
	// has no parent-death signal, so a worker orphaned by a guardian crash
	// must also stop on its own shortly after that deadline.
	deadline := time.AfterFunc(targetWorkerTimeout+targetWorkerWaitDelay, func() {
		fmt.Fprintln(stderr, "enterprise hooks: target worker exceeded its deadline")
		os.Exit(targetWorkerExitDeadline)
	})
	defer deadline.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), targetWorkerTimeout)
	defer cancel()
	result, err := invokeTargetOperation(ctx, TargetCredentials{UserHome: home, UID: request.UID, GID: request.GID}, op, request.Payload)
	if err != nil {
		return respond(targetWorkerResponse{Error: err.Error()}, 0)
	}
	return respond(targetWorkerResponse{OK: true, Payload: result}, 0)
}

// dropToTargetCredentials permanently replaces the process credentials with
// exactly the target uid, its primary gid and no other groups. A worker that
// was not started by root may only continue as its own identity.
func dropToTargetCredentials(uid, gid int) error {
	dropped := false
	if os.Geteuid() == 0 {
		if err := syscall.Setgroups([]int{gid}); err != nil {
			return fmt.Errorf("set supplementary groups: %w", err)
		}
		if err := syscall.Setgid(gid); err != nil {
			return fmt.Errorf("set gid: %w", err)
		}
		if err := syscall.Setuid(uid); err != nil {
			return fmt.Errorf("set uid: %w", err)
		}
		dropped = true
	}
	if os.Getuid() != uid || os.Geteuid() != uid {
		return fmt.Errorf("process runs as uid=%d euid=%d", os.Getuid(), os.Geteuid())
	}
	if os.Getgid() != gid || os.Getegid() != gid {
		return fmt.Errorf("process runs as gid=%d egid=%d", os.Getgid(), os.Getegid())
	}
	if dropped {
		groups, err := syscall.Getgroups()
		if err != nil {
			return fmt.Errorf("inspect supplementary groups: %w", err)
		}
		for _, group := range groups {
			if group != gid {
				return fmt.Errorf("supplementary group %d survived the drop", group)
			}
		}
	}
	if err := verifySavedTargetIDs(uid, gid); err != nil {
		return err
	}
	if err := syscall.Seteuid(0); err == nil {
		return errors.New("process can still regain uid 0")
	}
	return nil
}

func defaultTargetWorkerExecutableFromPath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve target worker executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve target worker executable: %w", err)
	}
	return executable, nil
}
