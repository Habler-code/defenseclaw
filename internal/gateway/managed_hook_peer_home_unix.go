// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// managedHookPeerHomeTTL bounds how long a resolved home is reused, so a
// moved or recreated account is picked up without restarting the gateway.
const managedHookPeerHomeTTL = 5 * time.Minute

// managedHookPeerHome resolves the home directory of a kernel-verified
// hook-socket caller through the platform account database (NSS on Linux,
// DirectoryService-backed os/user on macOS). Directory users therefore
// resolve too. An unresolvable home is empty: callers must not fall back to
// the gateway's own home, which belongs to the service account.
var managedHookPeerHome = func(uid int) string {
	return managedHookPeerHomes.lookup(uid)
}

var managedHookPeerHomes = &managedHookPeerHomeCache{
	newResolver: func() unixidentity.Resolver {
		return unixidentity.Default(context.Background())
	},
	now: time.Now,
}

type managedHookPeerHomeCache struct {
	mu          sync.Mutex
	resolver    unixidentity.Resolver
	resolvedAt  time.Time
	newResolver func() unixidentity.Resolver
	now         func() time.Time
}

func (c *managedHookPeerHomeCache) lookup(uid int) string {
	if uid < 0 {
		return ""
	}
	c.mu.Lock()
	if c.resolver == nil || c.now().Sub(c.resolvedAt) > managedHookPeerHomeTTL {
		c.resolver = c.newResolver()
		c.resolvedAt = c.now()
	}
	resolver := c.resolver
	c.mu.Unlock()
	if resolver == nil {
		return ""
	}
	account, err := resolver.LookupUID(uid)
	if err != nil || account.UID != uid {
		return ""
	}
	return normalizeManagedHookPeerHome(account.Home)
}

// normalizeManagedHookPeerHome keeps only an absolute, clean home below the
// root directory; anything else is treated as unresolved.
func normalizeManagedHookPeerHome(home string) string {
	if home == "" || !filepath.IsAbs(home) {
		return ""
	}
	cleaned := filepath.Clean(home)
	if cleaned != home && cleaned+"/" != home {
		return ""
	}
	if cleaned == string(filepath.Separator) {
		return ""
	}
	return cleaned
}
