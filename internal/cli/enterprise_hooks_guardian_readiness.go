// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// guardianReadinessStateTrustCheck gates the gateway-side read. The
// readiness literal is diagnostic health, not authorization, but it is still
// only honored when the file carries the same administrator-only-writable
// contract as the protected authorization ledger beside it, so a file the
// gateway (or any other non-administrator) could have written is reported as
// unknown rather than trusted.
var guardianReadinessStateTrustCheck = func(path string) error {
	return managed.ValidateTrustedFilePath(path, "hook guardian readiness state")
}

// writeEnterpriseHookGuardianReadinessState publishes the guardian's
// waiting_for_targets / ready literal at guardianstate.PathForDataDir, the
// same path newGuardianReadinessStateReader resolves in the gateway. The
// file is written exactly like the protected authorization and activation
// records in that directory: only into an already-trusted directory, through
// the protected machine-file writer, with the administrator-owned
// gateway-read-only ownership, and re-verified afterwards. It never creates
// or re-permissions the directory, so it cannot widen who may write there.
func writeEnterpriseHookGuardianReadinessState(dataDir, state string) (string, error) {
	path := guardianstate.PathForDataDir(dataDir)
	body, err := guardianstate.Encode(state)
	if err != nil {
		return path, err
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return path, fmt.Errorf("hook guardian authorization directory %s does not exist yet: %w", dir, os.ErrNotExist)
		}
		return path, fmt.Errorf("inspect hook guardian authorization directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return path, fmt.Errorf("hook guardian authorization path is not a trusted directory: %s", dir)
	}
	if err := enterpriseHookAuthorizationDirTrustCheck(dir); err != nil {
		return path, err
	}
	if err := writeEnterpriseHookProtectedFile(path, body); err != nil {
		return path, err
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return path, fmt.Errorf("make hook guardian readiness state readable: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return path, fmt.Errorf("set hook guardian readiness state ownership: %w", err)
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(path); err != nil {
		return path, err
	}
	return path, nil
}

// newGuardianReadinessStateReader is the gateway sidecar's probe for the
// guardian readiness literal. It resolves the path through the same helper
// as the writer and returns StateUnknown (the safe waiting_for_targets
// default) for a missing, unreadable, malformed, or untrusted file, and for
// a `ready` the guardian has not re-published within
// guardianstate.ReadyMaxAge (a stopped or crashed guardian cannot leave a
// stale ready behind).
func newGuardianReadinessStateReader(dataDir string) func() string {
	path := guardianstate.PathForDataDir(dataDir)
	return func() string {
		if err := guardianReadinessStateTrustCheck(path); err != nil {
			return guardianstate.StateUnknown
		}
		return guardianstate.ReadCurrentState(path, time.Now())
	}
}

// guardianReadinessAfterReconcile maps one watch-loop reconcile outcome onto
// the published readiness literal. Only a reconcile that returned no error,
// left no target failed, and published its protected state and exact
// enrollment set (StateErr == nil) is ready; runEnterpriseHookReconcileOnce
// returns a nil error for incomplete runs, so the run fields must be checked.
// Pending (deferred, signed-out) targets do not withhold ready.
func guardianReadinessAfterReconcile(run enterpriseHookReconcileRun, err error) string {
	if err != nil || run.Failures > 0 || run.StateErr != nil {
		return guardianstate.StateWaitingForTargets
	}
	return guardianstate.StateReady
}

// enterpriseHookReconcileProgress records when a running watch-loop
// reconcile pass last finished a target.
type enterpriseHookReconcileProgress struct {
	mu   sync.Mutex
	last time.Time
}

type enterpriseHookReconcileProgressKey struct{}

func newEnterpriseHookReconcileProgress(now time.Time) *enterpriseHookReconcileProgress {
	return &enterpriseHookReconcileProgress{last: now}
}

func (p *enterpriseHookReconcileProgress) note(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last = now
}

func (p *enterpriseHookReconcileProgress) since(now time.Time) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return now.Sub(p.last)
}

// withEnterpriseHookReconcileProgress returns ctx carrying progress for one
// reconcile pass.
func withEnterpriseHookReconcileProgress(ctx context.Context, progress *enterpriseHookReconcileProgress) context.Context {
	return context.WithValue(ctx, enterpriseHookReconcileProgressKey{}, progress)
}

// noteEnterpriseHookReconcileProgress records that the pass running under ctx
// finished a target. Outside a watch-loop pass it does nothing.
func noteEnterpriseHookReconcileProgress(ctx context.Context) {
	if ctx == nil {
		return
	}
	if progress, _ := ctx.Value(enterpriseHookReconcileProgressKey{}).(*enterpriseHookReconcileProgress); progress != nil {
		progress.note(time.Now())
	}
}

// keepGuardianReadyDuringPass re-publishes ready every interval while one
// reconcile pass runs, for a guardian whose last published readiness is
// ready. It skips a refresh once the pass has finished no target for longer
// than stall, so a pass stuck in one target still lets the ready age out of
// guardianstate.ReadyMaxAge. The returned stop waits for the refresher to
// exit, so the pass outcome published after it is never overwritten.
func keepGuardianReadyDuringPass(w io.Writer, progress *enterpriseHookReconcileProgress, interval, stall time.Duration) (stop func()) {
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-quit:
				return
			case <-ticker.C:
				if progress.since(time.Now()) > stall {
					continue
				}
				writeGuardianStateOrLog(w, guardianstate.StateReady)
			}
		}
	}()
	return func() {
		close(quit)
		<-done
	}
}
