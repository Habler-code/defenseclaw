// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// TargetOperation is one named unit of work that must run with a target
// user's own credentials. Requests and results cross a process boundary on
// Unix (see target_worker_unix.go), so both are JSON values; an operation
// must derive every path it touches from its request and the validated
// target rather than from process-global state.
type TargetOperation func(ctx context.Context, target TargetCredentials, payload json.RawMessage) (any, error)

var (
	targetOperationsMu sync.RWMutex
	targetOperations   = map[string]TargetOperation{}
)

// RegisterTargetOperation makes op available to RunTargetOperation and to
// the per-target worker. Registration belongs in package init so the worker
// process, which runs the same executable, sees the same table.
func RegisterTargetOperation(name string, op TargetOperation) {
	name = strings.TrimSpace(name)
	if name == "" || op == nil {
		panic("enterprise hooks: target operation registration requires a name and a function")
	}
	targetOperationsMu.Lock()
	defer targetOperationsMu.Unlock()
	if _, exists := targetOperations[name]; exists {
		panic(fmt.Sprintf("enterprise hooks: target operation %q registered twice", name))
	}
	targetOperations[name] = op
}

func lookupTargetOperation(name string) (TargetOperation, bool) {
	targetOperationsMu.RLock()
	defer targetOperationsMu.RUnlock()
	op, ok := targetOperations[name]
	return op, ok
}

// RunTargetOperation validates target and runs the registered operation name
// with that user's own credentials, decoding its result into response (which
// may be nil). A root process on Unix never changes its own credentials: it
// runs the operation in a short-lived worker process that has permanently
// become the target user. Native Windows keeps its thread-scoped
// impersonation boundary.
func RunTargetOperation(ctx context.Context, target TargetCredentials, name string, request, response any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	name = strings.TrimSpace(name)
	op, ok := lookupTargetOperation(name)
	if !ok {
		return fmt.Errorf("enterprise hooks: unknown target operation %q", name)
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("enterprise hooks: encode target operation %s request: %w", name, err)
	}
	result, err := runTargetOperation(ctx, target, name, op, payload)
	if err != nil {
		return err
	}
	if response == nil {
		return nil
	}
	if err := decodeTargetOperationJSON(result, response); err != nil {
		return fmt.Errorf("enterprise hooks: decode target operation %s result: %w", name, err)
	}
	return nil
}

func invokeTargetOperation(ctx context.Context, target TargetCredentials, op TargetOperation, payload json.RawMessage) (json.RawMessage, error) {
	result, err := op(ctx, target, payload)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: encode target operation result: %w", err)
	}
	return encoded, nil
}

// DecodeTargetOperationRequest strictly decodes one operation request.
func DecodeTargetOperationRequest(payload json.RawMessage, request any) error {
	return decodeTargetOperationJSON(payload, request)
}

func decodeTargetOperationJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}
