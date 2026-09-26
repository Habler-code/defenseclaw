// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"testing"
)

// Deferred staging keeps the lock state of an active DefenseClaw Claude Code
// policy. When it publishes the first one, it follows the administrator's
// claude_code.allow_unmanaged_hooks setting instead of always locking, so the
// opt-out also admits an outranking HKLM policy that carries the hooks without
// allowManagedHooksOnly.
func TestDeferredClaudeCodeAllowUnmanagedHooks(t *testing.T) {
	errRead := errors.New("read the published lock")
	for _, tc := range []struct {
		name       string
		active     bool
		configured bool
		published  bool
		readErr    error
		want       bool
		wantRead   bool
	}{
		{name: "first policy is locked by default"},
		{name: "first policy follows the opt-out", configured: true, want: true},
		{name: "active locked policy keeps its lock", active: true, configured: true, wantRead: true},
		{name: "active unlocked policy keeps its state", active: true, published: true, want: true, wantRead: true},
		{name: "unreadable active policy fails", active: true, configured: true, readErr: errRead, wantRead: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := false
			got, err := deferredClaudeCodeAllowUnmanagedHooks(tc.active, tc.configured, func() (bool, error) {
				read = true
				return tc.published, tc.readErr
			})
			if read != tc.wantRead {
				t.Fatalf("published lock state read=%t, want %t", read, tc.wantRead)
			}
			if tc.readErr != nil {
				if !errors.Is(err, tc.readErr) {
					t.Fatalf("error = %v, want %v", err, tc.readErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("allow unmanaged hooks = (%t, %v), want (%t, nil)", got, err, tc.want)
			}
		})
	}
}
