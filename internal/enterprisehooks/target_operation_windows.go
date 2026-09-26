//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"encoding/json"
)

// runTargetOperation keeps native Windows on its thread-scoped token
// impersonation boundary; impersonation does not leak to other threads.
func runTargetOperation(
	ctx context.Context,
	target TargetCredentials,
	_ string,
	op TargetOperation,
	payload json.RawMessage,
) (json.RawMessage, error) {
	var result json.RawMessage
	err := runAsTarget(target, func() error {
		var opErr error
		result, opErr = invokeTargetOperation(ctx, target, op, payload)
		return opErr
	})
	return result, err
}

// RunTargetWorkerIfRequested is a no-op on Windows, which has no per-target
// worker process.
func RunTargetWorkerIfRequested() (bool, int) {
	return false, 0
}
