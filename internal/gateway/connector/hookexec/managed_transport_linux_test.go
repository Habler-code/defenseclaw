// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func managedTestAccountIsTrustedServiceAccount() bool {
	uid, err := lookupLinuxManagedServiceUID()
	return err == nil && uid == uint32(os.Getuid())
}

func procNetV4(endpoint managedIPv4Endpoint) string {
	return fmt.Sprintf("%08X:%04X", binary.NativeEndian.Uint32(endpoint.addr[:]), endpoint.port)
}

func procNetV4Mapped(endpoint managedIPv4Endpoint) string {
	return fmt.Sprintf("0000000000000000%08X%08X:%04X",
		binary.NativeEndian.Uint32([]byte{0, 0, 0xff, 0xff}),
		binary.NativeEndian.Uint32(endpoint.addr[:]),
		endpoint.port)
}

func procNetRow(local, remote, state string, uid int, inode int) string {
	return fmt.Sprintf("   0: %s %s %s 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 20 4 30 10 -1",
		local, remote, state, uid, inode)
}

const procNetHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"

func parseProcNetFixture(t *testing.T, rows ...string) []linuxTCPSocketRow {
	t.Helper()
	parsed, err := parseProcNetTCP(strings.NewReader(strings.Join(append([]string{procNetHeader}, rows...), "\n")))
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestCheckLinuxGatewaySocketsUsesListenerOwner(t *testing.T) {
	const gatewayUID, otherUID = 995, 1000
	client := managedIPv4Endpoint{addr: [4]byte{127, 0, 0, 1}, port: 50000}
	server := managedIPv4Endpoint{addr: [4]byte{127, 0, 0, 1}, port: 18970}
	port := fmt.Sprintf("%04X", server.port)
	anyV4 := "00000000:" + port
	anyV6 := "00000000000000000000000000000000:" + port
	trusted := func(uid uint32) bool { return uid == 0 || uid == gatewayUID }

	queued := procNetRow(procNetV4(server), procNetV4(client), "01", 0, 0)
	clientRow := procNetRow(procNetV4(client), procNetV4(server), "01", otherUID, 11)
	cases := []struct {
		name    string
		rows    []string
		wantErr string
	}{
		{name: "gateway listener, queued connection", rows: []string{
			procNetRow(procNetV4(server), "00000000:0000", "0A", gatewayUID, 7), clientRow, queued}},
		{name: "root listener", rows: []string{
			procNetRow(procNetV4(server), "00000000:0000", "0A", 0, 7), clientRow, queued}},
		{name: "unprivileged listener, queued connection", rows: []string{
			procNetRow(procNetV4(server), "00000000:0000", "0A", otherUID, 7), clientRow, queued},
			wantErr: "owned by uid 1000"},
		{name: "accepted by an unprivileged process", rows: []string{
			procNetRow(procNetV4(server), "00000000:0000", "0A", gatewayUID, 7), clientRow,
			procNetRow(procNetV4(server), procNetV4(client), "01", otherUID, 12)},
			wantErr: "accepted by uid 1000"},
		{name: "exact listener wins over wildcard", rows: []string{
			procNetRow(procNetV4(server), "00000000:0000", "0A", gatewayUID, 7),
			procNetRow(anyV6, "00000000000000000000000000000000:0000", "0A", otherUID, 8), clientRow, queued}},
		{name: "wildcard listeners must all be trusted", rows: []string{
			procNetRow(anyV4, "00000000:0000", "0A", gatewayUID, 7),
			procNetRow(anyV6, "00000000000000000000000000000000:0000", "0A", otherUID, 8), clientRow, queued},
			wantErr: "owned by uid 1000"},
		{name: "dual-stack gateway listener", rows: []string{
			procNetRow(anyV6, "00000000000000000000000000000000:0000", "0A", gatewayUID, 8), clientRow,
			procNetRow(procNetV4Mapped(server), procNetV4Mapped(client), "01", 0, 0)}},
		{name: "connection not visible yet", rows: []string{
			procNetRow(procNetV4(server), "00000000:0000", "0A", gatewayUID, 7), clientRow},
			wantErr: "not established"},
		{name: "time-wait remnant is not the connection", rows: []string{
			procNetRow(procNetV4(server), "00000000:0000", "0A", gatewayUID, 7), clientRow,
			procNetRow(procNetV4(server), procNetV4(client), "06", 0, 0)},
			wantErr: "not established"},
		{name: "no listener", rows: []string{clientRow, queued}, wantErr: "no listening socket"},
		{name: "duplicate connection rows", rows: []string{
			procNetRow(procNetV4(server), "00000000:0000", "0A", gatewayUID, 7), queued, queued},
			wantErr: "2 sockets"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkLinuxGatewaySockets(parseProcNetFixture(t, tc.rows...), client, server, trusted)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("check = %v, want trusted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("check = %v, want %q", err, tc.wantErr)
			}
		})
	}
	if _, _, err := parseProcNetEndpoint("00000000000000000000000001000000:4A1A"); err == nil {
		t.Fatal("a native IPv6 address must not match an IPv4 connection")
	}
}

func TestVerifyManagedGatewayListenerLinuxResolvesServiceAccount(t *testing.T) {
	listener := listenManagedUnixTransport(t)
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client, server, err := managedConnEndpoints(conn)
	if err != nil {
		t.Fatal(err)
	}
	previousTable, previousService := managedLinuxSocketTable, managedLinuxServiceUID
	defer func() { managedLinuxSocketTable, managedLinuxServiceUID = previousTable, previousService }()
	for _, tc := range []struct {
		name       string
		owner      int
		serviceUID uint32
		serviceErr error
		trusted    bool
	}{
		{name: "root", owner: 0, serviceErr: errors.New("no account"), trusted: true},
		{name: "service account", owner: 995, serviceUID: 995, trusted: true},
		{name: "other local user", owner: 1000, serviceUID: 995},
		{name: "service account missing", owner: 995, serviceErr: errors.New("no account")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := parseProcNetFixture(t,
				procNetRow(procNetV4(server), "00000000:0000", "0A", tc.owner, 7),
				procNetRow(procNetV4(server), procNetV4(client), "01", 0, 0),
			)
			managedLinuxSocketTable = func() ([]linuxTCPSocketRow, error) { return rows, nil }
			managedLinuxServiceUID = func() (uint32, error) { return tc.serviceUID, tc.serviceErr }
			if err := verifyManagedGatewayListener(conn); tc.trusted != (err == nil) {
				t.Fatalf("verify = %v, trusted=%v", err, tc.trusted)
			}
		})
	}
}

// TestLinuxSocketTableReportsLiveListenerOwner reads the running kernel's
// tables for an IPv4 listener and for a dual-stack listener that receives
// the IPv4 connection as a mapped socket. The listener this process owns
// must read back as this process's uid.
func TestLinuxSocketTableReportsLiveListenerOwner(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "tcp" {
				address = ":0"
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				t.Skipf("listen %s: %v", network, err)
			}
			defer listener.Close()
			port := listener.Addr().(*net.TCPAddr).Port
			conn, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			client, server, err := managedConnEndpoints(conn)
			if err != nil {
				t.Fatal(err)
			}
			self := uint32(os.Getuid())
			onlySelf := func(uid uint32) bool { return uid == self }
			for attempt := 0; attempt < 20; attempt++ {
				var rows []linuxTCPSocketRow
				rows, err = readLinuxTCPSocketTable()
				if err != nil {
					t.Fatal(err)
				}
				err = checkLinuxGatewaySockets(rows, client, server, onlySelf)
				if !errors.Is(err, errManagedListenerPending) {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("own listener not recognised: %v", err)
			}
			if self != 0 {
				rows, err := readLinuxTCPSocketTable()
				if err != nil {
					t.Fatal(err)
				}
				rootOnly := func(uid uint32) bool { return uid == 0 }
				if err := checkLinuxGatewaySockets(rows, client, server, rootOnly); err == nil {
					t.Fatal("an unprivileged listener was reported as root-owned")
				}
			}
		})
	}
}

func TestRequireInitialLinuxUserNamespace(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, content string
		ok            bool
	}{
		{name: "initial", content: "         0          0 4294967295\n", ok: true},
		{name: "nested-root-mapping", content: "         0       1000          1\n"},
		{name: "partial-identity", content: "         0          0      65536\n"},
		{name: "several-ranges", content: "0 0 1000\n1000 1000 4294966295\n"},
		{name: "empty", content: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := dir + "/" + tc.name
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := requireInitialLinuxUserNamespace(path); tc.ok != (err == nil) {
				t.Fatalf("requireInitialLinuxUserNamespace = %v, want ok=%v", err, tc.ok)
			}
		})
	}
	if err := requireInitialLinuxUserNamespace(dir + "/missing"); err == nil {
		t.Fatal("a missing uid_map was accepted")
	}
	if err := requireInitialLinuxUserNamespace(managedLinuxUIDMapPath); err != nil {
		t.Logf("this test process is not in the initial user namespace: %v", err)
	}
}

func TestVerifyManagedGatewayListenerLinuxRefusesNestedUserNamespace(t *testing.T) {
	listener := listenManagedUnixTransport(t)
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	previousMap, previousTable := managedLinuxUIDMapPath, managedLinuxSocketTable
	defer func() { managedLinuxUIDMapPath, managedLinuxSocketTable = previousMap, previousTable }()
	path := t.TempDir() + "/uid_map"
	if err := os.WriteFile(path, []byte("0 1000 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	managedLinuxUIDMapPath = path
	managedLinuxSocketTable = func() ([]linuxTCPSocketRow, error) {
		t.Fatal("socket table read inside a nested user namespace")
		return nil, nil
	}
	if err := verifyManagedGatewayListener(conn); err == nil {
		t.Fatal("verify accepted a nested user namespace")
	}
}
