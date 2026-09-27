// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"sync"
)

// A reconcile pass handles its targets one after another, and after the
// credential switch a target user can stop or block their own per-target
// worker until its deadline. The stall guard limits what one user can cost
// the other users in a pass to that single deadline.
type targetWorkerStallGuard struct {
	mu      sync.Mutex
	stalled map[int]struct{}
}

type targetWorkerStallGuardKey struct{}

// WithTargetWorkerStallGuard returns a context for one reconcile pass. Once
// a per-target worker for a user does not finish before its deadline, later
// workers for that user in the same pass fail at once instead of each
// waiting for the full deadline. Those targets are reported as failures and
// retried on the next pass.
func WithTargetWorkerStallGuard(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, targetWorkerStallGuardKey{}, &targetWorkerStallGuard{stalled: map[int]struct{}{}})
}

// TargetWorkerStallGuardActive reports whether ctx carries a stall guard
// from WithTargetWorkerStallGuard.
func TargetWorkerStallGuardActive(ctx context.Context) bool {
	return targetWorkerStallGuardFrom(ctx) != nil
}

func targetWorkerStallGuardFrom(ctx context.Context) *targetWorkerStallGuard {
	if ctx == nil {
		return nil
	}
	guard, _ := ctx.Value(targetWorkerStallGuardKey{}).(*targetWorkerStallGuard)
	return guard
}

func (g *targetWorkerStallGuard) isStalled(uid int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, stalled := g.stalled[uid]
	return stalled
}

func (g *targetWorkerStallGuard) markStalled(uid int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stalled[uid] = struct{}{}
}
