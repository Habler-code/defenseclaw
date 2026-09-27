// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
)

func TestCodexRequestHelpersResolveHomeAgainstTheVerifiedCaller(t *testing.T) {
	plain := codexHookRequest{CWD: "/work"}
	if got, want := plain.resolvedActiveHome(), trustedSameHostHome(); got != want {
		t.Fatalf("request without a handler-resolved home=%q want the per-user home %q", got, want)
	}
	peerCtx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: "/home/alice"})
	if got := plain.withTrustedActiveHome(peerCtx).resolvedActiveHome(); got != "/home/alice" {
		t.Fatalf("hook-socket request home=%q want /home/alice", got)
	}
	unresolved := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1002})
	if got := plain.withTrustedActiveHome(unresolved).resolvedActiveHome(); got != "" {
		t.Fatalf("an unresolved caller home fell back to %q", got)
	}
	if got, want := plain.withTrustedActiveHome(context.Background()).resolvedActiveHome(), trustedSameHostHome(); got != want {
		t.Fatalf("per-user handler home=%q want %q", got, want)
	}
}

func TestTrustedActiveHomeIsEmptyOffTheHookSocketOnAServiceAccountGateway(t *testing.T) {
	marked := withServiceAccountGateway(context.Background())
	if got := trustedActiveHome(marked); got != "" {
		t.Fatalf("a request off the verified hook socket resolved home %q on a service-account gateway", got)
	}
	peerCtx := withManagedHookPeer(marked, managedHookPeer{UID: 1001, Home: "/home/alice"})
	if got := trustedActiveHome(peerCtx); got != "/home/alice" {
		t.Fatalf("hook-socket caller home=%q", got)
	}
	if got, want := trustedActiveHome(context.Background()), trustedSameHostHome(); got != want {
		t.Fatalf("per-user gateway home=%q want %q", got, want)
	}
}
