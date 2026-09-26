//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const testWindowsTargetOperationEcho = "enterprise-hooks.test.windows-echo"

type testWindowsTargetEcho struct {
	Message string `json:"message"`
	Fail    bool   `json:"fail,omitempty"`
}

func init() {
	RegisterTargetOperation(testWindowsTargetOperationEcho, func(_ context.Context, target TargetCredentials, payload json.RawMessage) (any, error) {
		var request testWindowsTargetEcho
		if err := DecodeTargetOperationRequest(payload, &request); err != nil {
			return nil, err
		}
		if request.Fail {
			return nil, errors.New(request.Message)
		}
		return testWindowsTargetEcho{Message: request.Message + "@" + target.SID}, nil
	})
}

// Native Windows runs a registered operation under the same impersonation
// boundary as RunAsTarget; only its request and result cross as JSON.
func TestRunTargetOperationUsesWindowsImpersonationBoundary(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Skipf("current Windows token identity unavailable: %v", err)
	}
	if windowsEnterpriseSystemIdentity(user.User.Sid) {
		t.Skip("test requires an interactive Windows identity")
	}
	home, err := windowsEnterpriseTokenProfileDirectory(token)
	if err != nil {
		t.Skipf("current Windows profile unavailable: %v", err)
	}
	target := TargetCredentials{UserHome: home, SID: user.User.Sid.String()}
	var reply testWindowsTargetEcho
	if err := RunTargetOperation(context.Background(), target, testWindowsTargetOperationEcho,
		testWindowsTargetEcho{Message: "hello"}, &reply); err != nil {
		t.Fatalf("RunTargetOperation: %v", err)
	}
	if reply.Message != "hello@"+target.SID {
		t.Fatalf("reply = %+v", reply)
	}
	err = RunTargetOperation(context.Background(), target, testWindowsTargetOperationEcho,
		testWindowsTargetEcho{Message: "enterprise hooks: specific failure", Fail: true}, nil)
	if err == nil || err.Error() != "enterprise hooks: specific failure" {
		t.Fatalf("operation failure = %v, want its own message", err)
	}
	err = RunTargetOperation(context.Background(), target, "enterprise-hooks.test.missing", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown target operation") {
		t.Fatalf("unknown operation = %v", err)
	}
}
