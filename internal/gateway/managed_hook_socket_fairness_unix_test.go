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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// startTestHookSocketServer runs the real standalone hook socket server on a
// temporary socket and returns the socket path and the API server.
func startTestHookSocketServer(t *testing.T) (string, *APIServer) {
	t.Helper()
	socket, api, _ := startTestHookSocketServerWithLedger(t, "")
	return socket, api
}

// startTestHookSocketServerWithLedger also installs a guardian authorization
// ledger (trusted without the ownership checks) and returns the audit store.
func startTestHookSocketServerWithLedger(t *testing.T, ledger string) (string, *APIServer, *audit.Store) {
	t.Helper()
	dir := shortGatewaySocketDir(t)
	socket := filepath.Join(dir, "hook.sock")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if ledger != "" {
		t.Setenv(managed.HookGuardianAuthorizationDirEnv, "")
		if err := os.MkdirAll(managed.HookGuardianAuthorizationDir(dataDir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(managed.HookGuardianAuthorizationPath(dataDir), []byte(ledger), 0o600); err != nil {
			t.Fatal(err)
		}
		restoreValidate := validateManagedGuardianAuthorization
		validateManagedGuardianAuthorization = func(string, string) error { return nil }
		t.Cleanup(func() { validateManagedGuardianAuthorization = restoreValidate })
	}
	current, err := osuser.Current()
	if err != nil {
		t.Fatal(err)
	}
	restoreDescriptor := loadStandaloneRuntimeDescriptor
	restoreInherited := inheritedHookListener
	t.Cleanup(func() {
		loadStandaloneRuntimeDescriptor = restoreDescriptor
		inheritedHookListener = restoreInherited
	})
	loadStandaloneRuntimeDescriptor = func(string) (*managed.RuntimeDescriptor, error) {
		return &managed.RuntimeDescriptor{
			SchemaVersion: managed.RuntimeDescriptorSchemaVersion,
			Profile:       managed.ProfileStandalone,
			ServiceUser:   current.Username,
			ServiceUID:    os.Getuid(),
			APIAddr:       managed.StandaloneAPIAddr,
			HookSocket:    socket,
		}, nil
	}
	inheritedHookListener = func() (net.Listener, bool, error) { return nil, false, nil }

	fixture := newSidecarRuntimeFixture(t, true)
	fingerprintEngine, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := fixture.store
	logger := audit.NewLogger(store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{
		runtime: fixture.runtime, redactionEngine: fingerprintEngine,
	})
	cfg := &config.Config{DeploymentMode: "managed_enterprise", DataDir: dataDir}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Mode = "observe"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	api.SetConnectorRegistry(connector.NewDefaultRegistry())
	// The refusal rows come from the API's own canonical runtime binding.
	api.bindOTLPObservabilityRuntime(fixture.runtime)

	ctx, cancel := context.WithCancel(context.Background())
	server, listener, err := api.newManagedHookSocketServer(ctx, func(h http.Handler) http.Handler { return h })
	if err != nil || server == nil {
		cancel()
		t.Fatalf("hook socket server: %v %v", server, err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
	})
	return socket, api, store
}

// hookSocketClient opens a fresh connection for every request, so each
// request is a new accepted connection on the server.
func hookSocketClient(socket string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
}

func hookSocketPost(client *http.Client, path string, body []byte) (int, string, error) {
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:18970"+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(data), nil
}

// slowPeerResolver answers every uid at once except slowUID, whose lookup
// blocks until release is closed (a directory user whose NSS lookup hangs).
type slowPeerResolver struct {
	unixidentity.Resolver
	slowUID int
	started chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (r *slowPeerResolver) LookupUID(uid int) (unixidentity.Account, error) {
	r.calls.Add(1)
	if uid == r.slowUID {
		r.once.Do(func() { close(r.started) })
		<-r.release
	}
	return unixidentity.Account{Name: fmt.Sprintf("user%d", uid), UID: uid, Home: fmt.Sprintf("/home/user%d", uid)}, nil
}

func useTestPeerResolver(t *testing.T, resolver unixidentity.Resolver) {
	t.Helper()
	previous := managedHookPeerHomes
	managedHookPeerHomes = &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver { return resolver },
		now:         time.Now,
	}
	t.Cleanup(func() { managedHookPeerHomes = previous })
}

// TestManagedHookSocketSlowAccountLookupDoesNotDelayOtherCallers: net/http
// runs ConnContext in its single accept loop. The caller's account lookup
// must not run there, or one directory user whose lookup hangs holds up the
// hook connections of every other user on the host.
func TestManagedHookSocketSlowAccountLookupDoesNotDelayOtherCallers(t *testing.T) {
	resolver := &slowPeerResolver{slowUID: 5001, started: make(chan struct{}), release: make(chan struct{})}
	useTestPeerResolver(t, resolver)
	var accepted atomic.Int32
	restoreCredentials := hookSocketPeerCredentials
	hookSocketPeerCredentials = func(net.Conn) (peercred.Credentials, error) {
		// The first accepted connection is the slow caller, every later
		// one another account.
		if accepted.Add(1) == 1 {
			return peercred.Credentials{UID: 5001, GID: 5001, PID: 101}, nil
		}
		return peercred.Credentials{UID: 5002, GID: 5002, PID: 102}, nil
	}
	t.Cleanup(func() { hookSocketPeerCredentials = restoreCredentials })
	socket, _ := startTestHookSocketServer(t)

	slowDone := make(chan error, 1)
	go func() {
		_, _, err := hookSocketPost(hookSocketClient(socket, 20*time.Second), "/api/v1/not-a-hook-route", []byte(`{}`))
		slowDone <- err
	}()
	select {
	case <-resolver.started:
	case <-time.After(5 * time.Second):
		close(resolver.release)
		t.Fatal("the slow caller's account lookup never started")
	}

	start := time.Now()
	status, body, err := hookSocketPost(hookSocketClient(socket, 3*time.Second), "/api/v1/not-a-hook-route", []byte(`{}`))
	elapsed := time.Since(start)
	close(resolver.release)
	if err != nil {
		t.Fatalf("another account's request waited behind a slow account lookup: %v after %s", err, elapsed)
	}
	if status != http.StatusForbidden || elapsed > 2*time.Second {
		t.Fatalf("other caller = %d %q after %s, want a prompt refusal of the unknown route", status, body, elapsed)
	}
	if err := <-slowDone; err != nil {
		t.Fatalf("the slow caller's own request failed: %v", err)
	}
}

// transientPeerResolver fails every lookup with a directory error that is not
// a definitive "no such account".
type transientPeerResolver struct {
	unixidentity.Resolver
	calls atomic.Int32
	err   error
}

func (r *transientPeerResolver) LookupUID(int) (unixidentity.Account, error) {
	r.calls.Add(1)
	return unixidentity.Account{}, r.err
}

// TestManagedHookPeerLookupReusesAFailedLookupBriefly: a directory outage must
// cost one lookup per uid per retry interval, not one (or two: name and home)
// per connection, and a definitive "no such account" is kept for the full TTL.
func TestManagedHookPeerLookupReusesAFailedLookupBriefly(t *testing.T) {
	for _, test := range []struct {
		name       string
		err        error
		retryAfter time.Duration
	}{
		{"transient", errors.New("getent: timed out"), managedHookPeerLookupRetry},
		{"not found", unixidentity.ErrNotFound, managedHookPeerHomeTTL},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := &transientPeerResolver{err: test.err}
			now := time.Unix(2_000_000, 0)
			cache := &managedHookPeerHomeCache{
				newResolver: func() unixidentity.Resolver { return resolver },
				now:         func() time.Time { return now },
			}
			for i := 0; i < 3; i++ {
				if home, name := cache.lookup(4001), cache.lookupName(4001); home != "" || name != "" {
					t.Fatalf("failed lookup resolved %q %q", home, name)
				}
			}
			if got := resolver.calls.Load(); got != 1 {
				t.Fatalf("resolver calls inside the retry interval = %d, want 1", got)
			}
			now = now.Add(test.retryAfter - time.Second)
			cache.lookup(4001)
			if got := resolver.calls.Load(); got != 1 {
				t.Fatalf("resolver asked again before the interval ended (%d calls)", got)
			}
			now = now.Add(2 * time.Second)
			cache.lookup(4001)
			if got := resolver.calls.Load(); got != 2 {
				t.Fatalf("resolver calls after the interval = %d, want 2", got)
			}
		})
	}
}

// TestManagedHookPeerLookupSharesALookupInFlight: concurrent connections of
// one uid wait for the same lookup instead of each starting one.
func TestManagedHookPeerLookupSharesALookupInFlight(t *testing.T) {
	resolver := &slowPeerResolver{slowUID: 6001, started: make(chan struct{}), release: make(chan struct{})}
	cache := &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver { return resolver },
		now:         time.Now,
	}
	var wg sync.WaitGroup
	homes := make([]string, 8)
	for i := range homes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			homes[i] = cache.lookup(6001)
		}(i)
	}
	<-resolver.started
	if home := cache.lookup(6002); home != "/home/user6002" {
		t.Fatalf("another uid waited for or lost its lookup: %q", home)
	}
	close(resolver.release)
	wg.Wait()
	for _, home := range homes {
		if home != "/home/user6001" {
			t.Fatalf("shared lookup answered %q", home)
		}
	}
	if got := resolver.calls.Load(); got != 2 {
		t.Fatalf("resolver calls = %d, want one per uid", got)
	}
}

// TestManagedHookSocketRateLimitsOneCallerWithoutSlowingAnother is a load
// test with two accounts: uid 7001 floods the hook socket from many
// connections while uid 7002 keeps calling. uid 7001's excess gets a prompt
// "rate limited" answer, and uid 7002 is never limited or held up.
func TestManagedHookSocketRateLimitsOneCallerWithoutSlowingAnother(t *testing.T) {
	useTestPeerResolver(t, &slowPeerResolver{slowUID: -1, started: make(chan struct{}), release: make(chan struct{})})
	restoreCredentials := hookSocketPeerCredentials
	hookSocketPeerCredentials = func(conn net.Conn) (peercred.Credentials, error) {
		// Each test client binds its socket to a name that says who it is.
		name := filepath.Base(conn.RemoteAddr().String())
		switch {
		case strings.HasPrefix(name, "a-"):
			return peercred.Credentials{UID: 7001, GID: 7001, PID: 201}, nil
		case strings.HasPrefix(name, "b-"):
			return peercred.Credentials{UID: 7002, GID: 7002, PID: 202}, nil
		}
		return peercred.Credentials{}, errors.New("unknown test caller")
	}
	t.Cleanup(func() { hookSocketPeerCredentials = restoreCredentials })
	socket, _ := startTestHookSocketServer(t)
	clientDir := shortGatewaySocketDir(t)
	var dialed atomic.Int64
	clientAs := func(prefix string, timeout time.Duration) *http.Client {
		return &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 64,
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					local := &net.UnixAddr{Name: filepath.Join(clientDir, fmt.Sprintf("%s%d", prefix, dialed.Add(1))), Net: "unix"}
					return net.DialUnix("unix", local, &net.UnixAddr{Name: socket, Net: "unix"})
				},
			},
		}
	}

	const floodFor = 1500 * time.Millisecond
	deadline := time.Now().Add(floodFor)
	flood := clientAs("a-", 5*time.Second)
	var admitted, limited, limitedWithReason, failed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				status, body, err := hookSocketPost(flood, "/api/v1/not-a-hook-route", []byte(`{}`))
				switch {
				case err != nil:
					failed.Add(1)
				case status == http.StatusTooManyRequests:
					limited.Add(1)
					if strings.Contains(body, managedHookReasonRateLimited) {
						limitedWithReason.Add(1)
					}
				default:
					admitted.Add(1)
				}
			}
		}()
	}

	other := clientAs("b-", 5*time.Second)
	var slowest time.Duration
	otherCalls := 0
	for time.Now().Before(deadline) {
		start := time.Now()
		status, body, err := hookSocketPost(other, "/api/v1/not-a-hook-route", []byte(`{}`))
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("uid 7002 request failed during uid 7001's flood: %v", err)
		}
		if status == http.StatusTooManyRequests {
			t.Fatalf("uid 7002 was rate limited by uid 7001's flood: %s", body)
		}
		if elapsed > slowest {
			slowest = elapsed
		}
		otherCalls++
		time.Sleep(20 * time.Millisecond)
	}
	wg.Wait()
	t.Logf("uid 7001: admitted=%d limited=%d failed=%d; uid 7002: calls=%d slowest=%s",
		admitted.Load(), limited.Load(), failed.Load(), otherCalls, slowest)
	if limited.Load() == 0 || limitedWithReason.Load() != limited.Load() {
		t.Fatalf("uid 7001's flood was not rate limited with a clear reason (limited=%d with reason=%d)",
			limited.Load(), limitedWithReason.Load())
	}
	// Burst plus the sustained rate over the flood, with slack for timing.
	if max := int64(hookCallerBurst + hookCallerRate*2 + 20); admitted.Load() > max {
		t.Fatalf("uid 7001 was admitted %d times in %s, want at most %d", admitted.Load(), floodFor, max)
	}
	if otherCalls == 0 || slowest > time.Second {
		t.Fatalf("uid 7002 calls=%d slowest=%s during the flood", otherCalls, slowest)
	}
}
