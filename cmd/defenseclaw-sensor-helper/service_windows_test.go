// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// statusAtWrite records how many service states had been reported when each
// log line was written, so a test can tell whether the reason for a failure
// reached the log before SCM was told the service is stopping.
type statusAtWrite struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	status   chan svc.Status
	reported []int
}

func (w *statusAtWrite) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reported = append(w.reported, len(w.status))
	return w.buffer.Write(p)
}

func (w *statusAtWrite) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

func runHelperServiceForTest(
	t *testing.T,
	serve func(context.Context) error,
	control func(chan<- svc.ChangeRequest),
) (uint32, *statusAtWrite, []svc.Status) {
	t.Helper()
	status := make(chan svc.Status, 16)
	writer := &statusAtWrite{status: status}
	service := &helperService{
		ctx:    context.Background(),
		serve:  serve,
		logger: slog.New(slog.NewTextHandler(writer, nil)),
	}
	requests := make(chan svc.ChangeRequest)
	done := make(chan uint32, 1)
	go func() {
		_, code := service.Execute(nil, requests, status)
		done <- code
	}()
	if control != nil {
		control(requests)
	}
	var code uint32
	select {
	case code = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("helper service did not return")
	}
	close(status)
	var reported []svc.Status
	for state := range status {
		reported = append(reported, state)
	}
	return code, writer, reported
}

// Under SCM, svc.Run returns only the dispatcher's result, so an error from
// serve is lost unless the handler records it. This is the failure #901 set
// out to explain: the helper's secured listener cannot bind, SCM shows exit
// code 1, and sensor-helper.log must say why.
func TestHelperServiceLogsServeFailureBeforeReportingStop(t *testing.T) {
	bindFailure := errors.New("bind the managed IPC socket: access is denied")
	code, writer, reported := runHelperServiceForTest(t, func(context.Context) error {
		return bindFailure
	}, nil)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 so SCM's recovery policy sees a failure", code)
	}
	output := writer.String()
	if !strings.Contains(output, "sensor helper exited") || !strings.Contains(output, bindFailure.Error()) {
		t.Fatalf("service log does not record the serve failure: %q", output)
	}
	// StartPending and Running were reported; StopPending was not yet.
	if len(writer.reported) != 1 || writer.reported[0] != 2 {
		t.Fatalf("serve failure was logged after %v reported states, want once after 2", writer.reported)
	}
	if len(reported) != 3 || reported[2].State != svc.StopPending {
		t.Fatalf("reported states = %+v, want StartPending, Running, StopPending", reported)
	}
}

func TestHelperServiceOrderlyStopLogsNothing(t *testing.T) {
	code, writer, _ := runHelperServiceForTest(t, func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}, func(requests chan<- svc.ChangeRequest) {
		requests <- svc.ChangeRequest{Cmd: svc.Stop}
	})
	if code != 0 {
		t.Fatalf("exit code = %d after an orderly stop, want 0", code)
	}
	if output := writer.String(); output != "" {
		t.Fatalf("orderly stop wrote to the service log: %q", output)
	}
}

func TestHelperServiceLogsErrorReturnedWhileStopping(t *testing.T) {
	stopFailure := errors.New("close the managed IPC listener: handle is invalid")
	code, writer, _ := runHelperServiceForTest(t, func(ctx context.Context) error {
		<-ctx.Done()
		return stopFailure
	}, func(requests chan<- svc.ChangeRequest) {
		requests <- svc.ChangeRequest{Cmd: svc.Stop}
	})
	if code != 0 {
		t.Fatalf("exit code = %d after a requested stop, want 0", code)
	}
	if output := writer.String(); !strings.Contains(output, stopFailure.Error()) {
		t.Fatalf("service log does not record the error returned while stopping: %q", output)
	}
}
