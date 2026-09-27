// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// A reconcile pass handles its targets one after another, and after the
// credential switch a target user can stop, block or slow their own
// per-target workers. Each user therefore gets one time budget per pass
// that all of that user's workers share: a worker runs only for what is
// left of it, and once it is used up (or a worker misses its deadline) no
// more workers start for that user in the pass. However many targets and
// workers a user has, they cost the other users at most that budget.
type targetWorkerPass struct {
	budget time.Duration

	mu    sync.Mutex
	users map[int]*targetWorkerPassUser
	// watch holds the watch paths an Install or Verify worker reported,
	// keyed by its request, so ResolveWatchPaths needs no worker of its own.
	watch map[string]WatchPathSet
}

type targetWorkerPassUser struct {
	spent   time.Duration
	stalled bool
}

type targetWorkerPassKey struct{}

// targetWorkerPassBudget is the worker time each user gets per reconcile
// pass: one worker deadline (targetWorkerTimeout on Unix).
var targetWorkerPassBudget = 2 * time.Minute

// WithTargetWorkerPass returns a context for one reconcile pass. In it a
// root guardian on Unix gives each target user's workers one shared time
// budget; once that user's workers have used it up, or one missed its
// deadline, later workers for that user fail at once. Those targets are
// reported as failures and retried on the next pass. Install and Verify
// workers in the pass also report the target's watch paths, which
// ResolveWatchPaths then returns without starting another worker.
func WithTargetWorkerPass(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, targetWorkerPassKey{}, &targetWorkerPass{
		budget: targetWorkerPassBudget,
		users:  map[int]*targetWorkerPassUser{},
		watch:  map[string]WatchPathSet{},
	})
}

// TargetWorkerPassActive reports whether ctx carries a reconcile pass from
// WithTargetWorkerPass.
func TargetWorkerPassActive(ctx context.Context) bool {
	return targetWorkerPassFrom(ctx) != nil
}

func targetWorkerPassFrom(ctx context.Context) *targetWorkerPass {
	if ctx == nil {
		return nil
	}
	pass, _ := ctx.Value(targetWorkerPassKey{}).(*targetWorkerPass)
	return pass
}

func (p *targetWorkerPass) user(uid int) *targetWorkerPassUser {
	user, ok := p.users[uid]
	if !ok {
		user = &targetWorkerPassUser{}
		p.users[uid] = user
	}
	return user
}

// remaining returns what is left of uid's budget, or false once it is used
// up or one of the user's workers missed its deadline.
func (p *targetWorkerPass) remaining(uid int) (time.Duration, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	user := p.user(uid)
	left := p.budget - user.spent
	if user.stalled || left <= 0 {
		user.stalled = true
		return 0, false
	}
	return left, true
}

// charge records that one of uid's workers ran for elapsed.
func (p *targetWorkerPass) charge(uid int, elapsed time.Duration, missedDeadline bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	user := p.user(uid)
	user.spent += elapsed
	if missedDeadline || user.spent >= p.budget {
		user.stalled = true
	}
}

func targetWorkerPassWatchKey(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (p *targetWorkerPass) storeWatchPaths(payload []byte, set WatchPathSet) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.watch[targetWorkerPassWatchKey(payload)] = set
}

func (p *targetWorkerPass) watchPaths(payload []byte) (WatchPathSet, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	set, ok := p.watch[targetWorkerPassWatchKey(payload)]
	return set, ok
}
