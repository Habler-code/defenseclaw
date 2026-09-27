//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The apply-target worker runs every user-home operation of the standalone
// Unix guardian with the target user's own uid and gid. The root guardian
// keeps token minting, the authorization ledger and file watching; it never
// Lstats, removes, chmods or writes inside a user home itself, so a user
// cannot race a root check-then-act, a Seteuid drop can never leak into
// the guardian's other goroutines, and NFS root_squash homes work.

const (
	enterpriseHookWorkerProtocolVersion = 1
	enterpriseHookWorkerRequestLimit    = 1 << 20
	enterpriseHookWorkerResponseLimit   = 8 << 20
	enterpriseHookWorkerStderrLimit     = 64 << 10
	enterpriseHookWorkerParallelism     = 4

	enterpriseHookWorkerOpApply          = "apply"
	enterpriseHookWorkerOpDiscover       = "discover"
	enterpriseHookWorkerOpForeignCleanup = "foreign_cleanup"

	enterpriseHookWorkerModeInstall        = "install"
	enterpriseHookWorkerModeVerify         = "verify"
	enterpriseHookWorkerModeVerifyOrRepair = "verify_or_repair"
	// enterpriseHookWorkerModeRemove tears down DefenseClaw's own per-user
	// registration (standalone uninstall).
	enterpriseHookWorkerModeRemove = "remove"
)

// enterpriseHookWorkerTimeout bounds one worker process.
var enterpriseHookWorkerTimeout = 60 * time.Second

// enterpriseHookWorkerPassthroughEnv are administrator-controlled service
// settings the worker needs; nothing else from root's environment reaches
// a process that runs as the user.
var enterpriseHookWorkerPassthroughEnv = []string{
	"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT",
	"DEFENSECLAW_CODEX_LOOPBACK_TRUST",
	enterprisehooks.TrustedBinPrefixesEnv,
}

type enterpriseHookWorkerOptions struct {
	ConnectorName                      string `json:"connector"`
	UserHome                           string `json:"user_home"`
	OwnerUID                           int    `json:"owner_uid"`
	OwnerGID                           int    `json:"owner_gid"`
	DataDir                            string `json:"data_dir,omitempty"`
	APIAddr                            string `json:"api_addr,omitempty"`
	ProxyAddr                          string `json:"proxy_addr,omitempty"`
	APIToken                           string `json:"api_token,omitempty"`
	OTLPPathToken                      string `json:"otlp_path_token,omitempty"`
	HookFailMode                       string `json:"hook_fail_mode,omitempty"`
	GuardrailMode                      string `json:"guardrail_mode,omitempty"`
	HILTEnabled                        bool   `json:"hilt_enabled,omitempty"`
	AgentVersion                       string `json:"agent_version,omitempty"`
	HookContractID                     string `json:"hook_contract_id,omitempty"`
	WorkspaceDir                       string `json:"workspace_dir,omitempty"`
	AllowMissingHookConfigRepair       bool   `json:"allow_missing_hook_config_repair,omitempty"`
	RecoveryHookContractLockUpdatedAt  string `json:"recovery_hook_contract_lock_updated_at,omitempty"`
	RecoveryHookContractEntryUpdatedAt string `json:"recovery_hook_contract_entry_updated_at,omitempty"`
}

type enterpriseHookWorkerTarget struct {
	Index               int                         `json:"index"`
	Mode                string                      `json:"mode"`
	PreviouslyProtected bool                        `json:"previously_protected,omitempty"`
	Options             enterpriseHookWorkerOptions `json:"options"`
}

type enterpriseHookWorkerRequest struct {
	Version    int                          `json:"version"`
	Operation  string                       `json:"operation"`
	UID        int                          `json:"uid"`
	GID        int                          `json:"gid"`
	User       string                       `json:"user"`
	Home       string                       `json:"home"`
	Standalone bool                         `json:"standalone"`
	Targets    []enterpriseHookWorkerTarget `json:"targets,omitempty"`
	Connectors []string                     `json:"connectors,omitempty"`
	// ForeignCleanup asks the worker to remove unapproved foreign hooks
	// from the user's own vendor config (foreign_cleanup operation).
	ForeignCleanup []enterpriseHookWorkerForeignCleanup `json:"foreign_cleanup,omitempty"`
}

// enterpriseHookWorkerForeignCleanup is one connector's foreign-hook
// cleanup; the parent resolves the policy from the administrator's config,
// which the worker cannot read.
type enterpriseHookWorkerForeignCleanup struct {
	Connector     string                                 `json:"connector"`
	HookBinary    string                                 `json:"hook_binary"`
	Policy        enterprisepolicy.PublicConnectorPolicy `json:"policy"`
	OwnedCommands []string                               `json:"owned_commands,omitempty"`
}

// enterpriseHookWorkerCleanupReport summarizes one connector's cleanup.
// It is user-influenced and only logged.
type enterpriseHookWorkerCleanupReport struct {
	Removed   []string `json:"removed,omitempty"`
	Reported  []string `json:"reported,omitempty"`
	BackupDir string   `json:"backup_dir,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type enterpriseHookWorkerTargetResult struct {
	Index    int                            `json:"index"`
	OK       bool                           `json:"ok"`
	Repaired bool                           `json:"repaired,omitempty"`
	Pending  bool                           `json:"pending,omitempty"`
	Error    string                         `json:"error,omitempty"`
	Result   *enterprisehooks.InstallResult `json:"result,omitempty"`
}

type enterpriseHookWorkerResponse struct {
	Version  int                                          `json:"version"`
	Targets  []enterpriseHookWorkerTargetResult           `json:"targets,omitempty"`
	Versions map[string]string                            `json:"versions,omitempty"`
	Reasons  map[string]string                            `json:"reasons,omitempty"`
	Cleanup  map[string]enterpriseHookWorkerCleanupReport `json:"cleanup,omitempty"`
	Error    string                                       `json:"error,omitempty"`
}

// enterpriseHookWorkerAccount is the resolved target the parent spawns
// a worker for.
type enterpriseHookWorkerAccount struct {
	UID  int
	GID  int
	User string
	Home string
}

var enterpriseHooksApplyTargetCmd = &cobra.Command{
	Use:    "apply-target",
	Short:  "Internal: apply or verify hooks for one user with that user's credentials",
	Hidden: true,
	Args:   cobra.NoArgs,
	// The worker runs as the target user, who cannot read the managed
	// config; it receives everything it needs on stdin.
	Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	RunE: func(cmd *cobra.Command, _ []string) error {
		// The parent kills the worker's session on timeout, but macOS has
		// no parent-death signal: never outlive the parent's deadline.
		time.AfterFunc(enterpriseHookWorkerTimeout+5*time.Second, func() { os.Exit(5) })
		if code := enterpriseHookWorkerMain(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()); code != 0 {
			return fmt.Errorf("enterprise hooks apply-target: worker failed (exit %d)", code)
		}
		return nil
	},
}

func init() {
	enterpriseHooksCmd.AddCommand(enterpriseHooksApplyTargetCmd)
}

// enterpriseHookWorkerMain is the worker process body. It returns a process
// exit code; per-target failures are reported in the response, not as a
// non-zero exit.
func enterpriseHookWorkerMain(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) int {
	if ctx == nil {
		ctx = context.Background()
	}
	respond := func(response enterpriseHookWorkerResponse, code int) int {
		response.Version = enterpriseHookWorkerProtocolVersion
		if err := json.NewEncoder(stdout).Encode(response); err != nil {
			fmt.Fprintf(stderr, "apply-target: write response: %v\n", err)
			return 2
		}
		return code
	}
	data, err := io.ReadAll(io.LimitReader(stdin, enterpriseHookWorkerRequestLimit+1))
	if err != nil || len(data) > enterpriseHookWorkerRequestLimit {
		return respond(enterpriseHookWorkerResponse{Error: "request is unreadable or too large"}, 3)
	}
	var request enterpriseHookWorkerRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return respond(enterpriseHookWorkerResponse{Error: "request is not valid JSON: " + err.Error()}, 3)
	}
	if err := validateEnterpriseHookWorkerIdentity(request); err != nil {
		return respond(enterpriseHookWorkerResponse{Error: err.Error()}, 4)
	}
	hardenEnterpriseHookWorkerProcess()
	applyEnterpriseHookWorkerLimits()
	enterprisehooks.SetStandaloneUnix(request.Standalone)
	switch request.Operation {
	case enterpriseHookWorkerOpApply:
		return respond(runEnterpriseHookWorkerApply(ctx, request), 0)
	case enterpriseHookWorkerOpDiscover:
		versions := map[string]string{}
		reasons := map[string]string{}
		for _, name := range request.Connectors {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			version, reason := enterpriseHookWorkerDiscoverVersion(ctx, request.Home, name, true)
			if version != "" {
				versions[name] = version
			} else if reason != "" {
				reasons[name] = reason
			}
		}
		return respond(enterpriseHookWorkerResponse{Versions: versions, Reasons: reasons}, 0)
	case enterpriseHookWorkerOpForeignCleanup:
		return respond(enterpriseHookWorkerResponse{Cleanup: runEnterpriseHookWorkerForeignCleanup(request, time.Now())}, 0)
	default:
		return respond(enterpriseHookWorkerResponse{Error: fmt.Sprintf("unknown operation %q", request.Operation)}, 3)
	}
}

// enterpriseHookWorkerDiscoverVersion is replaceable in tests.
var enterpriseHookWorkerDiscoverVersion = enterprisehooks.DiscoverUnixAgentVersion

func validateEnterpriseHookWorkerIdentity(request enterpriseHookWorkerRequest) error {
	if request.Version != enterpriseHookWorkerProtocolVersion {
		return fmt.Errorf("unsupported worker protocol version %d", request.Version)
	}
	if request.UID <= 0 || request.GID < 0 {
		return fmt.Errorf("worker refuses uid %d gid %d", request.UID, request.GID)
	}
	if os.Getuid() != request.UID || os.Geteuid() != request.UID ||
		os.Getgid() != request.GID || os.Getegid() != request.GID {
		return fmt.Errorf("worker runs as uid=%d/%d gid=%d/%d, want the target uid=%d gid=%d",
			os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), request.UID, request.GID)
	}
	home := filepath.Clean(strings.TrimSpace(request.Home))
	if !filepath.IsAbs(home) || home == "/" {
		return fmt.Errorf("worker home %q is not an absolute user home", request.Home)
	}
	for _, target := range request.Targets {
		if target.Options.OwnerUID != request.UID || target.Options.OwnerGID != request.GID ||
			filepath.Clean(target.Options.UserHome) != home {
			return fmt.Errorf("worker target %d does not belong to uid %d and home %s", target.Index, request.UID, home)
		}
	}
	return nil
}

// applyEnterpriseHookWorkerLimits drops core dumps (the request carries
// scoped tokens) and bounds files and descriptors the worker can create.
func applyEnterpriseHookWorkerLimits() {
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	lowerRlimit(syscall.RLIMIT_FSIZE, 256<<20)
	lowerRlimit(syscall.RLIMIT_NOFILE, 1024)
}

func lowerRlimit(resource int, limit uint64) {
	var current syscall.Rlimit
	if err := syscall.Getrlimit(resource, &current); err != nil {
		return
	}
	if current.Cur > limit || current.Cur == ^uint64(0) {
		current.Cur = limit
	}
	if current.Max > limit || current.Max == ^uint64(0) {
		current.Max = limit
	}
	_ = syscall.Setrlimit(resource, &current)
}

// enterpriseHookWorkerInstaller/Verifier are replaceable in tests.
var (
	enterpriseHookWorkerInstaller = enterprisehooks.Install
	enterpriseHookWorkerVerifier  = enterprisehooks.Verify
	enterpriseHookWorkerRemover   = enterprisehooks.RemoveUserHooks
)

func runEnterpriseHookWorkerApply(ctx context.Context, request enterpriseHookWorkerRequest) enterpriseHookWorkerResponse {
	registry := connector.NewDefaultRegistry()
	results := make([]enterpriseHookWorkerTargetResult, 0, len(request.Targets))
	for _, target := range request.Targets {
		opts := target.Options.installOptions(registry)
		outcome := enterpriseHookWorkerTargetResult{Index: target.Index}
		var result enterprisehooks.InstallResult
		var err error
		switch target.Mode {
		case enterpriseHookWorkerModeInstall:
			result, err = enterpriseHookWorkerInstaller(ctx, opts)
		case enterpriseHookWorkerModeVerify:
			result, err = enterpriseHookWorkerVerifier(ctx, opts)
		case enterpriseHookWorkerModeVerifyOrRepair:
			if !target.PreviouslyProtected {
				result, err = enterpriseHookWorkerInstaller(ctx, opts)
				break
			}
			result, err = enterpriseHookWorkerVerifier(ctx, opts)
			if err != nil {
				result, err = enterpriseHookWorkerInstaller(ctx, opts)
				outcome.Repaired = err == nil
			}
		case enterpriseHookWorkerModeRemove:
			err = enterpriseHookWorkerRemover(ctx, opts)
		default:
			err = fmt.Errorf("unknown worker mode %q", target.Mode)
		}
		if err != nil {
			// Pending only when the home itself went away mid-operation;
			// a missing file inside an available home is a failure.
			outcome.Pending = enterprisehooks.PendingTargetError(err) &&
				enterprisehooks.CheckUnixTargetHome(request.Home, request.UID).State == enterprisehooks.HomePending
			if !outcome.Pending {
				outcome.Error = err.Error()
			}
		} else {
			outcome.OK = true
			if target.Mode != enterpriseHookWorkerModeRemove {
				outcome.Result = &result
			}
		}
		results = append(results, outcome)
	}
	return enterpriseHookWorkerResponse{Targets: results}
}

func (o enterpriseHookWorkerOptions) installOptions(registry *connector.Registry) enterprisehooks.InstallOptions {
	return enterprisehooks.InstallOptions{
		ConnectorName:                      o.ConnectorName,
		UserHome:                           o.UserHome,
		OwnerUID:                           o.OwnerUID,
		OwnerGID:                           o.OwnerGID,
		DataDir:                            o.DataDir,
		APIAddr:                            o.APIAddr,
		ProxyAddr:                          o.ProxyAddr,
		APIToken:                           o.APIToken,
		OTLPPathToken:                      o.OTLPPathToken,
		HookFailMode:                       o.HookFailMode,
		GuardrailMode:                      o.GuardrailMode,
		HILTEnabled:                        o.HILTEnabled,
		AgentVersion:                       o.AgentVersion,
		HookContractID:                     o.HookContractID,
		WorkspaceDir:                       o.WorkspaceDir,
		Registry:                           registry,
		AllowMissingHookConfigRepair:       o.AllowMissingHookConfigRepair,
		RecoveryHookContractLockUpdatedAt:  o.RecoveryHookContractLockUpdatedAt,
		RecoveryHookContractEntryUpdatedAt: o.RecoveryHookContractEntryUpdatedAt,
	}
}

func enterpriseHookWorkerOptionsFrom(opts enterprisehooks.InstallOptions) enterpriseHookWorkerOptions {
	return enterpriseHookWorkerOptions{
		ConnectorName:                      opts.ConnectorName,
		UserHome:                           opts.UserHome,
		OwnerUID:                           opts.OwnerUID,
		OwnerGID:                           opts.OwnerGID,
		DataDir:                            opts.DataDir,
		APIAddr:                            opts.APIAddr,
		ProxyAddr:                          opts.ProxyAddr,
		APIToken:                           opts.APIToken,
		OTLPPathToken:                      opts.OTLPPathToken,
		HookFailMode:                       opts.HookFailMode,
		GuardrailMode:                      opts.GuardrailMode,
		HILTEnabled:                        opts.HILTEnabled,
		AgentVersion:                       opts.AgentVersion,
		HookContractID:                     opts.HookContractID,
		WorkspaceDir:                       opts.WorkspaceDir,
		AllowMissingHookConfigRepair:       opts.AllowMissingHookConfigRepair,
		RecoveryHookContractLockUpdatedAt:  opts.RecoveryHookContractLockUpdatedAt,
		RecoveryHookContractEntryUpdatedAt: opts.RecoveryHookContractEntryUpdatedAt,
	}
}

// Parent side.

var (
	// enterpriseHookWorkerExecutable resolves the binary the worker runs.
	enterpriseHookWorkerExecutable = defaultEnterpriseHookWorkerExecutable
	// enterpriseHookWorkerArgs are the worker's command-line arguments.
	enterpriseHookWorkerArgs = []string{"enterprise", "hooks", "apply-target"}
	// enterpriseHookWorkerExtraEnv is appended to the worker environment;
	// tests use it to select the helper process.
	enterpriseHookWorkerExtraEnv []string
	// enterpriseHookWorkerLog receives the worker's bounded stderr.
	enterpriseHookWorkerLog io.Writer = os.Stderr
)

func defaultEnterpriseHookWorkerExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve guardian executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve guardian executable: %w", err)
	}
	if os.Geteuid() == 0 {
		// A root parent hands this binary to every user; it must be
		// administrator-owned so no user can substitute it.
		if err := managed.ValidateTrustedFilePath(exe, "hook guardian worker executable"); err != nil {
			return "", err
		}
	}
	return exe, nil
}

type workerOutputBuffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

func (b *workerOutputBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.limit {
		b.exceeded = true
		if remaining := b.limit - b.buf.Len(); remaining > 0 {
			b.buf.Write(p[:remaining])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

// runEnterpriseHookWorker spawns one worker for account and returns its
// decoded response.
func runEnterpriseHookWorker(
	ctx context.Context,
	account enterpriseHookWorkerAccount,
	request enterpriseHookWorkerRequest,
) (enterpriseHookWorkerResponse, error) {
	if account.UID <= 0 {
		return enterpriseHookWorkerResponse{}, fmt.Errorf("refusing a worker for uid %d", account.UID)
	}
	if os.Geteuid() != 0 && (os.Geteuid() != account.UID || os.Getegid() != account.GID) {
		return enterpriseHookWorkerResponse{}, fmt.Errorf("a non-root guardian can only run a worker for itself (uid %d)", os.Geteuid())
	}
	request.Version = enterpriseHookWorkerProtocolVersion
	request.UID, request.GID = account.UID, account.GID
	request.User, request.Home = account.User, account.Home
	payload, err := json.Marshal(request)
	if err != nil {
		return enterpriseHookWorkerResponse{}, err
	}
	exe, err := enterpriseHookWorkerExecutable()
	if err != nil {
		return enterpriseHookWorkerResponse{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, enterpriseHookWorkerTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, enterpriseHookWorkerArgs...)
	cmd.Dir = "/"
	cmd.Env = enterpriseHookWorkerEnvironment(account)
	cmd.Stdin = bytes.NewReader(payload)
	stdout := &workerOutputBuffer{limit: enterpriseHookWorkerResponseLimit}
	stderr := &workerOutputBuffer{limit: enterpriseHookWorkerStderrLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = enterpriseHookWorkerSysProcAttr(account)
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// The worker leads its own session; kill the whole group so an
		// agent `--version` child cannot outlive the timeout.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	runErr := cmd.Run()
	forwardEnterpriseHookWorkerStderr(account, stderr)
	if ctx.Err() != nil {
		return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d timed out: %w", account.UID, ctx.Err())
	}
	if stdout.exceeded {
		return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d returned an oversized response", account.UID)
	}
	var response enterpriseHookWorkerResponse
	decoder := json.NewDecoder(bytes.NewReader(stdout.buf.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		if runErr != nil {
			return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d failed: %w", account.UID, runErr)
		}
		return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d returned invalid JSON: %w", account.UID, err)
	}
	if response.Version != enterpriseHookWorkerProtocolVersion {
		return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d speaks protocol %d", account.UID, response.Version)
	}
	if response.Error != "" {
		return response, fmt.Errorf("worker for uid %d: %s", account.UID, response.Error)
	}
	if runErr != nil {
		return response, fmt.Errorf("worker for uid %d failed: %w", account.UID, runErr)
	}
	return response, nil
}

// enterpriseHookWorkerPath lets connector setup find an agent where
// discovery found it (OmniGent locates itself on PATH), after the system
// directories so they always win. The worker runs as the user, so the
// user-owned entries grant nothing the user does not already have.
func enterpriseHookWorkerPath(home string) string {
	parts := []string{"/usr/bin", "/bin"}
	seen := map[string]bool{"/usr/bin": true, "/bin": true}
	for _, dir := range enterprisehooks.UnixAgentSearchDirs(home) {
		dir = filepath.Clean(dir)
		if seen[dir] || !filepath.IsAbs(dir) || strings.ContainsAny(dir, ":\x00") {
			continue
		}
		seen[dir] = true
		parts = append(parts, dir)
	}
	return strings.Join(parts, ":")
}

func enterpriseHookWorkerEnvironment(account enterpriseHookWorkerAccount) []string {
	env := []string{
		"HOME=" + account.Home,
		"USER=" + account.User,
		"LOGNAME=" + account.User,
		"PATH=" + enterpriseHookWorkerPath(account.Home),
		"LANG=C",
		"LC_ALL=C",
	}
	for _, name := range enterpriseHookWorkerPassthroughEnv {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return append(env, enterpriseHookWorkerExtraEnv...)
}

func forwardEnterpriseHookWorkerStderr(account enterpriseHookWorkerAccount, stderr *workerOutputBuffer) {
	if enterpriseHookWorkerLog == nil || stderr.buf.Len() == 0 {
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(stderr.buf.Bytes()))
	scanner.Buffer(make([]byte, 0, 4096), enterpriseHookWorkerStderrLimit)
	for scanner.Scan() {
		line := strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return ' '
			}
			return r
		}, scanner.Text())
		fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] worker uid=%d: %s\n", account.UID, line)
	}
	if stderr.exceeded {
		fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] worker uid=%d: stderr truncated\n", account.UID)
	}
}

// enterpriseHookWorkerJob is one user's batch.
type enterpriseHookWorkerJob struct {
	Account enterpriseHookWorkerAccount
	Request enterpriseHookWorkerRequest
}

type enterpriseHookWorkerOutcome struct {
	Job      enterpriseHookWorkerJob
	Response enterpriseHookWorkerResponse
	Err      error
}

// enterpriseHookWorkerRunner is replaceable in tests.
var enterpriseHookWorkerRunner = runEnterpriseHookWorker

// runEnterpriseHookWorkerPool runs one worker per job with bounded
// parallelism and returns outcomes in job order.
func runEnterpriseHookWorkerPool(ctx context.Context, jobs []enterpriseHookWorkerJob, parallelism int) []enterpriseHookWorkerOutcome {
	if parallelism <= 0 {
		parallelism = enterpriseHookWorkerParallelism
	}
	outcomes := make([]enterpriseHookWorkerOutcome, len(jobs))
	semaphore := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	for i := range jobs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			response, err := enterpriseHookWorkerRunner(ctx, jobs[i].Account, jobs[i].Request)
			outcomes[i] = enterpriseHookWorkerOutcome{Job: jobs[i], Response: response, Err: err}
		}(i)
	}
	wg.Wait()
	return outcomes
}

// sortedWorkerJobs returns jobs ordered by uid for deterministic logs.
func sortedWorkerJobs(byUID map[int]*enterpriseHookWorkerJob) []enterpriseHookWorkerJob {
	uids := make([]int, 0, len(byUID))
	for uid := range byUID {
		uids = append(uids, uid)
	}
	sort.Ints(uids)
	jobs := make([]enterpriseHookWorkerJob, 0, len(uids))
	for _, uid := range uids {
		jobs = append(jobs, *byUID[uid])
	}
	return jobs
}

var errEnterpriseHookWorkerNoResult = errors.New("worker returned no result for this target")
