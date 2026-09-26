// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package hookexec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var managedUnixTransportTestMu sync.Mutex

func swapManagedListenerVerifier(t *testing.T, verify func(net.Conn) error) {
	t.Helper()
	managedUnixTransportTestMu.Lock()
	previous := managedEnterpriseVerifyListener
	managedEnterpriseVerifyListener = verify
	t.Cleanup(func() {
		managedEnterpriseVerifyListener = previous
		managedUnixTransportTestMu.Unlock()
	})
}

func listenManagedUnixTransport(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

// captureManagedUnixBytes accepts one connection and reports every byte the
// client wrote before closing.
func captureManagedUnixBytes(listener net.Listener) <-chan []byte {
	result := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		data, _ := io.ReadAll(conn)
		result <- data
	}()
	return result
}

func serveManagedUnixAllow(t *testing.T, listener net.Listener) <-chan string {
	t.Helper()
	requests := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			requests <- ""
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 8192)
		n, _ := conn.Read(buffer)
		requests <- string(buffer[:n])
		_, _ = io.WriteString(conn,
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"action\":\"allow\"}")
	}()
	return requests
}

func TestManagedUnixTransportRejectsUntrustedListenerBeforeHTTPBytes(t *testing.T) {
	listener := listenManagedUnixTransport(t)
	received := captureManagedUnixBytes(listener)
	swapManagedListenerVerifier(t, func(net.Conn) error {
		return errors.New("gateway listener is owned by uid 501, want root")
	})

	client, err := managedEnterpriseHTTPClient(time.Second, listener.Addr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Post(
		"http://"+listener.Addr().String()+"/api/v1/claude-code/hook",
		"application/json",
		strings.NewReader(`{"secret":"must-not-leak"}`),
	)
	if err == nil || !errors.Is(err, errManagedGatewayPeerUnverified) {
		t.Fatalf("untrusted listener error = %v, want %v", err, errManagedGatewayPeerUnverified)
	}
	if got := <-received; len(got) != 0 {
		t.Fatalf("untrusted listener received %d request bytes: %q", len(got), got)
	}
}

func TestManagedUnixTransportSendsOnlyAfterListenerIsVerified(t *testing.T) {
	listener := listenManagedUnixTransport(t)
	requests := serveManagedUnixAllow(t, listener)
	var verified []string
	swapManagedListenerVerifier(t, func(conn net.Conn) error {
		verified = append(verified, conn.RemoteAddr().String())
		return nil
	})

	client, err := managedEnterpriseHTTPClient(time.Second, listener.Addr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if !transport.DisableKeepAlives || transport.Proxy != nil {
		t.Fatalf("managed transport must disable keep-alives and proxies: keepalives-disabled=%v proxy=%v",
			transport.DisableKeepAlives, transport.Proxy != nil)
	}
	response, err := client.Post(
		"http://"+listener.Addr().String()+"/api/v1/claude-code/hook",
		"application/json",
		strings.NewReader(`{}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if got := <-requests; !strings.HasPrefix(got, "POST /api/v1/claude-code/hook HTTP/1.1") {
		t.Fatalf("request = %q", got)
	}
	if len(verified) != 1 || verified[0] != listener.Addr().String() {
		t.Fatalf("verified connections = %v, want exactly the gateway connection", verified)
	}
}

func TestManagedUnixTransportRetriesOnlyPendingLookups(t *testing.T) {
	listener := listenManagedUnixTransport(t)
	requests := serveManagedUnixAllow(t, listener)
	calls := 0
	swapManagedListenerVerifier(t, func(net.Conn) error {
		calls++
		if calls < 3 {
			return errManagedListenerPending
		}
		return nil
	})
	client, err := managedEnterpriseHTTPClient(time.Second, listener.Addr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get("http://" + listener.Addr().String() + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	<-requests
	if calls != 3 {
		t.Fatalf("verifier calls = %d, want 3", calls)
	}
}

func TestManagedUnixTransportFailsClosedWhenOwnershipStaysUnknown(t *testing.T) {
	listener := listenManagedUnixTransport(t)
	received := captureManagedUnixBytes(listener)
	calls := 0
	swapManagedListenerVerifier(t, func(net.Conn) error {
		calls++
		return errManagedListenerPending
	})
	client, err := managedEnterpriseHTTPClient(2*time.Second, listener.Addr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Post("http://"+listener.Addr().String()+"/api/v1/codex/hook", "application/json",
		strings.NewReader(`{"secret":"must-not-leak"}`))
	if !errors.Is(err, errManagedGatewayPeerUnverified) {
		t.Fatalf("error = %v, want %v", err, errManagedGatewayPeerUnverified)
	}
	if calls != managedListenerLookupAttempts {
		t.Fatalf("verifier calls = %d, want %d bounded attempts", calls, managedListenerLookupAttempts)
	}
	if got := <-received; len(got) != 0 {
		t.Fatalf("unverified listener received %q", got)
	}
}

func TestManagedUnixTransportPinsCanonicalDialTarget(t *testing.T) {
	for _, value := range []string{
		"", "localhost:18970", "[::1]:18970", "127.0.0.2:18970", "0.0.0.0:18970",
		"127.0.0.1:018970", " 127.0.0.1:18970", "10.0.0.1:18970",
	} {
		if _, err := managedEnterpriseHTTPClient(time.Second, value, ""); !errors.Is(err, errManagedGatewayPeerUnverified) {
			t.Fatalf("managedEnterpriseHTTPClient(%q) error = %v, want peer-unverified", value, err)
		}
	}
	swapManagedListenerVerifier(t, func(net.Conn) error { return nil })
	client, err := managedEnterpriseHTTPClient(time.Second, "127.0.0.1:18970", "")
	if err != nil {
		t.Fatal(err)
	}
	// A redirect or an absolute URL for another port must never be dialed.
	_, err = client.Get("http://127.0.0.1:18971/api/v1/codex/hook")
	if !errors.Is(err, errManagedGatewayPeerUnverified) {
		t.Fatalf("off-target dial error = %v, want peer-unverified", err)
	}
	if client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("managed client must not follow redirects")
	}
}

// TestManagedUnixTransportRefusesUnprivilegedListenerWithRealKernel is the
// end-to-end regression for a same-host process holding the gateway port:
// the listener here is owned by the unprivileged test account, so the kernel
// lookup must refuse it and the listener must not receive a byte.
func TestManagedUnixTransportRefusesUnprivilegedListenerWithRealKernel(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root-owned test listener is a trusted managed gateway owner")
	}
	if managedTestAccountIsTrustedServiceAccount() {
		t.Skip("test account is the managed gateway service account")
	}
	listener := listenManagedUnixTransport(t)
	received := captureManagedUnixBytes(listener)
	managedUnixTransportTestMu.Lock()
	defer managedUnixTransportTestMu.Unlock()

	client, err := managedEnterpriseHTTPClient(2*time.Second, listener.Addr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Post("http://"+listener.Addr().String()+"/api/v1/claude-code/hook", "application/json",
		strings.NewReader(`{"secret":"must-not-leak"}`))
	if !errors.Is(err, errManagedGatewayPeerUnverified) {
		t.Fatalf("unprivileged listener error = %v, want %v", err, errManagedGatewayPeerUnverified)
	}
	if strings.Contains(err.Error(), "not established") {
		t.Fatalf("kernel lookup never located the connected socket: %v", err)
	}
	if got := <-received; len(got) != 0 {
		t.Fatalf("unprivileged listener received %d bytes: %q", len(got), got)
	}
}

// TestRunManagedHookFailsClosedAgainstUnprivilegedListener drives the hook
// entrypoint: a managed hook configured to fail open must still fail closed
// with the stable reason and must not deliver its bearer to the listener.
func TestRunManagedHookFailsClosedAgainstUnprivilegedListener(t *testing.T) {
	if os.Geteuid() == 0 || managedTestAccountIsTrustedServiceAccount() {
		t.Skip("test account is a trusted managed gateway owner")
	}
	listener := listenManagedUnixTransport(t)
	received := captureManagedUnixBytes(listener)
	managedUnixTransportTestMu.Lock()
	defer managedUnixTransportTestMu.Unlock()

	home := t.TempDir()
	hookDir := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	token := "managed-scoped-token-must-not-leak"
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), Options{
		Connector:                 "claudecode",
		Event:                     "PreToolUse",
		APIAddr:                   listener.Addr().String(),
		FailMode:                  "open",
		Home:                      home,
		HookDir:                   hookDir,
		AuthenticatedManagedToken: &token,
		ManagedEnterprise:         true,
		Stdin:                     strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"true"}}`),
		Stdout:                    &stdout,
		Stderr:                    &stderr,
	})
	if got := <-received; len(got) != 0 {
		t.Fatalf("unprivileged listener received %d bytes: %q", len(got), got)
	}
	if code != 2 && !strings.Contains(stdout.String(), "deny") {
		t.Fatalf("managed hook did not fail closed: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), managedGatewayPeerUnverifiedReason) {
		t.Fatalf("stderr = %q, want stable reason %q", stderr.String(), managedGatewayPeerUnverifiedReason)
	}
}

func TestRunCodexNotifyManagedSkipsUnprivilegedListener(t *testing.T) {
	if os.Geteuid() == 0 || managedTestAccountIsTrustedServiceAccount() {
		t.Skip("test account is a trusted managed gateway owner")
	}
	listener := listenManagedUnixTransport(t)
	received := captureManagedUnixBytes(listener)
	managedUnixTransportTestMu.Lock()
	defer managedUnixTransportTestMu.Unlock()

	home := t.TempDir()
	hookDir := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	token := "managed-notify-token-must-not-leak"
	var stderr bytes.Buffer
	code := RunCodexNotify(context.Background(), Options{
		APIAddr:                   listener.Addr().String(),
		Home:                      home,
		HookDir:                   hookDir,
		AuthenticatedManagedToken: &token,
		ManagedEnterprise:         true,
		Stderr:                    &stderr,
	}, []byte(`{"type":"agent-turn-complete"}`))
	if code != 0 {
		t.Fatalf("notify exit = %d, want best-effort 0", code)
	}
	if got := <-received; len(got) != 0 {
		t.Fatalf("unprivileged listener received %d bytes: %q", len(got), got)
	}
	if got := strings.TrimSpace(stderr.String()); got != managedGatewayPeerUnverifiedReason {
		t.Fatalf("stderr = %q, want %q", got, managedGatewayPeerUnverifiedReason)
	}
}

// TestManagedUnixTransportAcceptsRootListenerWithRealKernel runs only as
// root (the privileged live check): a root process's own listener has the
// managed gateway's shape and must be accepted by the real kernel lookup.
func TestManagedUnixTransportAcceptsRootListenerWithRealKernel(t *testing.T) {
	if os.Geteuid() != 0 || os.Getuid() != 0 {
		t.Skip("requires root")
	}
	listener := listenManagedUnixTransport(t)
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := verifyManagedGatewayConn(context.Background(), conn); err != nil {
		t.Fatalf("root listener refused: %v", err)
	}
}
