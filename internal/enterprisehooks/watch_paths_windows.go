//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "context"

// Native Windows resolves watch paths through platformWatchDirs and
// platformWatchOwnedFiles.
func platformResolveWatchPaths(context.Context, InstallOptions) (WatchPathSet, bool) {
	return WatchPathSet{}, false
}
