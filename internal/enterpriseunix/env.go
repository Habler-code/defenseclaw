// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// CommandResult is the captured outcome of one external command.
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner executes host administration commands. The production runner only
// runs absolute paths with a fixed minimal environment; tests substitute a
// fake.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (CommandResult, error)
}

// EnvRunner is a Runner that can add environment variables to the fixed
// minimal environment; the lifecycle uses it to run the gateway CLI with
// the same managed pins the guardian service gets.
type EnvRunner interface {
	RunEnv(ctx context.Context, env []string, name string, args ...string) (CommandResult, error)
}

// ErrCommandNotFound reports that none of a command's absolute candidate
// paths exists on the host.
var ErrCommandNotFound = errors.New("command not found")

// commandCandidates lists the only locations a host tool is run from. The
// lifecycle never consults PATH: an administrator's shell or the MDM agent
// may carry an arbitrary one.
var commandCandidates = map[string][]string{
	"systemctl":        {"/usr/bin/systemctl", "/bin/systemctl"},
	"systemd-sysusers": {"/usr/bin/systemd-sysusers", "/bin/systemd-sysusers"},
	"getent":           {"/usr/bin/getent", "/bin/getent"},
	"useradd":          {"/usr/sbin/useradd", "/sbin/useradd"},
	"groupadd":         {"/usr/sbin/groupadd", "/sbin/groupadd"},
	"userdel":          {"/usr/sbin/userdel", "/sbin/userdel"},
	"groupdel":         {"/usr/sbin/groupdel", "/sbin/groupdel"},
	"dpkg":             {"/usr/bin/dpkg", "/bin/dpkg"},
	"rpm":              {"/usr/bin/rpm", "/bin/rpm"},
	"restorecon":       {"/usr/sbin/restorecon", "/sbin/restorecon"},
	"launchctl":        {"/bin/launchctl"},
	"dscl":             {"/usr/bin/dscl"},
	"pkgutil":          {"/usr/sbin/pkgutil"},
}

// ExecRunner is the production Runner.
type ExecRunner struct {
	// Timeout bounds every command; zero means two minutes.
	Timeout time.Duration
}

// Run executes name (a key of commandCandidates, or an absolute path) with
// args and a clean environment.
func (r ExecRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	return r.RunEnv(ctx, nil, name, args...)
}

// RunEnv is Run with extra KEY=VALUE environment entries.
func (r ExecRunner) RunEnv(ctx context.Context, extra []string, name string, args ...string) (CommandResult, error) {
	path, err := resolveCommand(name)
	if err != nil {
		return CommandResult{ExitCode: -1}, err
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}, extra...)
	cmd.Dir = "/"
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, remaining: 4 << 20}
	cmd.Stderr = &limitedWriter{w: &stderr, remaining: 1 << 20}
	runErr := cmd.Run()
	result := CommandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return result, fmt.Errorf("%s %s: exit %d: %s", name, strings.Join(args, " "), result.ExitCode, strings.TrimSpace(string(result.Stderr)))
		}
		return result, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), runErr)
	}
	return result, nil
}

func resolveCommand(name string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil
	}
	for _, candidate := range commandCandidates[name] {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%s: %w", name, ErrCommandNotFound)
}

type limitedWriter struct {
	w         io.Writer
	remaining int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.remaining <= 0 {
		return len(p), nil
	}
	n := len(p)
	if n > l.remaining {
		p = p[:l.remaining]
	}
	l.remaining -= len(p)
	_, err := l.w.Write(p)
	return n, err
}

// TrustKind names a trust check the lifecycle runs on an installed path.
type TrustKind int

const (
	// TrustAdminFile is an administrator-owned input (config, descriptor).
	TrustAdminFile TrustKind = iota
	// TrustRuntimeDir is a directory the service account may own.
	TrustRuntimeDir
)

// Env binds the lifecycle to one host. Zero values are replaced by
// production defaults in NewEnv.
type Env struct {
	GOOS string
	// Root prefixes every layout path. Production uses "" (the real
	// filesystem); tests use a temporary directory.
	Root   string
	Layout managed.StandaloneLayout

	Runner        Runner
	Services      ServiceManager
	Accounts      AccountManager
	MachinePolicy MachinePolicyManager

	Now     func() time.Time
	Geteuid func() int
	// Lchown changes ownership without following a symlink.
	Lchown func(path string, uid, gid int) error
	// OwnerOf reports a path's uid and gid without following a symlink.
	OwnerOf func(path string) (int, int, error)
	// Trust runs the managed trust checks on a rooted path.
	Trust func(path string, kind TrustKind) error
	// HealthGet fetches the gateway /health document.
	HealthGet func(ctx context.Context) (int, []byte, error)

	// ProductVersion is the version of the running lifecycle binary.
	ProductVersion string

	// SelfUnit names the service unit or launchd job this lifecycle run
	// executes inside (the config-apply trigger). The lifecycle never stops
	// or restarts that unit: doing so would kill its own transaction.
	SelfUnit string

	LockTimeout  time.Duration
	ReadyTimeout time.Duration
	PollInterval time.Duration
}

// NewEnv returns the production environment for goos.
func NewEnv(goos, productVersion string) (*Env, error) {
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		return nil, err
	}
	env := &Env{
		GOOS:           goos,
		Layout:         layout,
		Runner:         ExecRunner{},
		ProductVersion: productVersion,
	}
	env.fillDefaults()
	env.SelfUnit = selfUnitFromEnv(env.Services, os.Getenv(LifecycleUnitEnv))
	return env, nil
}

// DefaultLockWait is how long a lifecycle run waits for another run to
// finish before it reports busy (exit 75). MDM agents retry a busy run, so
// they get the answer promptly; the config-apply trigger passes a longer
// --lock-wait so a change made during another run is applied after it.
const DefaultLockWait = 5 * time.Second

// MaxLockWait bounds --lock-wait.
const MaxLockWait = 15 * time.Minute

// LifecycleUnitEnv is set by the units that run the lifecycle themselves
// (the config-apply service and launchd job) to their own name.
const LifecycleUnitEnv = "DEFENSECLAW_LIFECYCLE_UNIT"

// selfUnitFromEnv accepts only a unit the service manager manages, so the
// variable can only ever exempt a lifecycle entry point from quiescing.
func selfUnitFromEnv(services ServiceManager, value string) string {
	value = strings.TrimSpace(value)
	if value == "" || services == nil {
		return ""
	}
	for _, unit := range services.Units() {
		if unit.Name == value && (unit.Name == unitApplyService || unit.Name == labelApply) {
			return value
		}
	}
	return ""
}

func (e *Env) fillDefaults() {
	if e.Runner == nil {
		e.Runner = ExecRunner{}
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Geteuid == nil {
		e.Geteuid = os.Geteuid
	}
	if e.Lchown == nil {
		e.Lchown = os.Lchown
	}
	if e.OwnerOf == nil {
		e.OwnerOf = func(path string) (int, int, error) {
			uid, gid, _, err := statOwnerMode(path)
			return uid, gid, err
		}
	}
	if e.Trust == nil {
		e.Trust = defaultTrust
	}
	if e.HealthGet == nil {
		addr := e.Layout.APIAddr
		e.HealthGet = func(ctx context.Context) (int, []byte, error) { return httpHealth(ctx, addr) }
	}
	if e.Services == nil {
		e.Services = newServiceManager(e)
	}
	if e.Accounts == nil {
		e.Accounts = newAccountManager(e)
	}
	if e.MachinePolicy == nil {
		e.MachinePolicy = newMachinePolicyManager(e)
	}
	if e.LockTimeout <= 0 {
		e.LockTimeout = DefaultLockWait
	}
	if e.ReadyTimeout <= 0 {
		e.ReadyTimeout = 90 * time.Second
	}
	if e.PollInterval <= 0 {
		e.PollInterval = 500 * time.Millisecond
	}
}

// serviceEnvironment is the managed environment the guardian service gets
// (the systemd units and launchd plists set the same pins).
func (e *Env) serviceEnvironment() []string {
	env := []string{
		"DEFENSECLAW_HOME=" + e.Layout.DataDir,
		"DEFENSECLAW_CONFIG=" + e.Layout.ConfigPath,
		managed.DeploymentModeEnv + "=" + managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv + "=" + managed.ProfileStandalone,
		"DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=" + e.Layout.GuardianAuthDir,
	}
	if e.GOOS == "darwin" {
		env = append(env, "DEFENSECLAW_UNIX_SERVICE_ACCOUNT="+e.Layout.ServiceUser)
	}
	return env
}

// runGatewayCLI runs the installed gateway binary with the service
// environment, so its commands load the managed standalone config.
func (e *Env) runGatewayCLI(ctx context.Context, args ...string) (CommandResult, error) {
	gateway := filepath.Join(e.P(e.Layout.BinDir), binGateway)
	if runner, ok := e.Runner.(EnvRunner); ok {
		return runner.RunEnv(ctx, e.serviceEnvironment(), gateway, args...)
	}
	return e.Runner.Run(ctx, gateway, args...)
}

// P maps a canonical layout path onto the rooted filesystem.
func (e *Env) P(path string) string {
	if e.Root == "" {
		return path
	}
	return filepath.Join(e.Root, path)
}

func defaultTrust(path string, kind TrustKind) error {
	switch kind {
	case TrustAdminFile:
		return managed.ValidateTrustedFilePath(path, "managed file")
	case TrustRuntimeDir:
		return managed.ValidateTrustedRuntimeDir(path, "managed runtime directory")
	}
	return fmt.Errorf("unknown trust kind %d", kind)
}

// httpHealth probes the loopback gateway health endpoint without proxies.
func httpHealth(ctx context.Context, addr string) (int, []byte, error) {
	transport := &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/health", nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

// CurrentGOOS is the host OS; the CLI refuses a lifecycle for another OS.
func CurrentGOOS() string { return runtime.GOOS }
