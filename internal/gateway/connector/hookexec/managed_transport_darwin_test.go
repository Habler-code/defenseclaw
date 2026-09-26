// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func managedTestAccountIsTrustedServiceAccount() bool { return false }

type darwinPCBFixture struct {
	local, remote managedIPv4Endpoint
	uid           uint32
	lastPID       int32
	effectivePID  int32
	state         int32
	family        int32
}

func darwinTestEndpoint(port uint16) managedIPv4Endpoint {
	return managedIPv4Endpoint{addr: [4]byte{127, 0, 0, 1}, port: port}
}

// buildDarwinPCBList renders records in the kernel's pcblist_n framing:
// xinpgen, then six 8-byte-aligned xgen_n records per socket, then a
// trailing xinpgen.
func buildDarwinPCBList(records ...darwinPCBFixture) []byte {
	order := binary.LittleEndian
	header := make([]byte, 24)
	order.PutUint32(header[0:4], 24)
	order.PutUint32(header[4:8], uint32(len(records)))
	out := append([]byte(nil), header...)
	item := func(kind uint32, size int, fill func([]byte)) {
		body := make([]byte, size)
		order.PutUint32(body[0:4], uint32(size))
		order.PutUint32(body[4:8], kind)
		if fill != nil {
			fill(body)
		}
		out = append(out, body...)
		for len(out)%8 != 0 {
			out = append(out, 0)
		}
	}
	for _, record := range records {
		family := record.family
		if family == 0 {
			family = darwinAFInet
		}
		item(darwinXSOInpcb, 104, func(b []byte) {
			binary.BigEndian.PutUint16(b[darwinInpcbFPort:], record.remote.port)
			binary.BigEndian.PutUint16(b[darwinInpcbLPort:], record.local.port)
			b[darwinInpcbVFlag] = darwinInpVFlagIPv4
			copy(b[darwinInpcbFAddr4:], record.remote.addr[:])
			copy(b[darwinInpcbLAddr4:], record.local.addr[:])
		})
		item(darwinXSOSocket, 104, func(b []byte) {
			order.PutUint32(b[darwinSocketProto:], darwinIPProtoTCP)
			order.PutUint32(b[darwinSocketFamily:], uint32(family))
			order.PutUint32(b[darwinSocketUID:], record.uid)
			order.PutUint32(b[darwinSocketLastPID:], uint32(record.lastPID))
			order.PutUint32(b[darwinSocketEPID:], uint32(record.effectivePID))
		})
		item(darwinXSORcvBuf, 28, nil)
		item(darwinXSOSndBuf, 28, nil)
		item(darwinXSOStats, 164, nil)
		item(darwinXSOTCPCB, 204, func(b []byte) {
			order.PutUint32(b[darwinTCPCBState:], uint32(record.state))
		})
	}
	out = append(out, header...)
	return out
}

func TestFindDarwinServerSocketPolicy(t *testing.T) {
	const selfUID, selfPID = 501, 7000
	client := darwinTestEndpoint(50000)
	server := darwinTestEndpoint(18970)
	own := darwinPCBFixture{local: client, remote: server, uid: selfUID, lastPID: selfPID, state: darwinTCPSEstablish}
	gateway := darwinPCBFixture{local: server, remote: client, uid: 0, lastPID: 4242, state: darwinTCPSEstablish}

	record, err := findDarwinServerSocket(buildDarwinPCBList(own, gateway), client, server, selfUID, selfPID)
	if err != nil || record.uid != 0 || record.lastPID != 4242 {
		t.Fatalf("record = %+v, %v", record, err)
	}

	pending := gateway
	pending.state = 3
	if _, err := findDarwinServerSocket(buildDarwinPCBList(own, pending), client, server, selfUID, selfPID); !errors.Is(err, errManagedListenerPending) {
		t.Fatalf("non-established server socket error = %v, want pending", err)
	}
	if _, err := findDarwinServerSocket(buildDarwinPCBList(own), client, server, selfUID, selfPID); !errors.Is(err, errManagedListenerPending) {
		t.Fatalf("missing server socket error = %v, want pending", err)
	}
	if _, err := findDarwinServerSocket(buildDarwinPCBList(own, gateway, gateway), client, server, selfUID, selfPID); err == nil || errors.Is(err, errManagedListenerPending) {
		t.Fatalf("duplicate server socket error = %v, want final failure", err)
	}
	// A layout this parser does not understand would misread the caller's
	// own socket; that must fail closed rather than trust the server record.
	misread := own
	misread.uid = 0
	if _, err := findDarwinServerSocket(buildDarwinPCBList(misread, gateway), client, server, selfUID, selfPID); err == nil || !strings.Contains(err.Error(), "layout") {
		t.Fatalf("uncalibrated layout error = %v", err)
	}
	wrongFamily := gateway
	wrongFamily.family = 1
	if _, err := findDarwinServerSocket(buildDarwinPCBList(own, wrongFamily), client, server, selfUID, selfPID); err == nil || !strings.Contains(err.Error(), "layout") {
		t.Fatalf("unexpected family error = %v", err)
	}
}

func TestParseDarwinTCPPCBListRejectsMalformedFraming(t *testing.T) {
	valid := buildDarwinPCBList(darwinPCBFixture{local: darwinTestEndpoint(1), remote: darwinTestEndpoint(2), state: darwinTCPSEstablish})
	for name, buffer := range map[string][]byte{
		"empty":             nil,
		"short header":      valid[:12],
		"truncated record":  valid[:len(valid)-40],
		"missing trailer":   valid[:len(valid)-24],
		"partial socket":    append(append([]byte(nil), valid[:24+104]...), valid[len(valid)-24:]...),
		"oversized trailer": append(append([]byte(nil), valid[:len(valid)-24]...), 0xff, 0xff, 0, 0, 0x10, 0, 0, 0),
	} {
		if _, err := parseDarwinTCPPCBList(buffer); err == nil {
			t.Fatalf("%s: malformed PCB list accepted", name)
		}
	}
	records, err := parseDarwinTCPPCBList(valid)
	if err != nil || len(records) != 1 {
		t.Fatalf("valid list = %v, %v", records, err)
	}
}

func TestVerifyManagedGatewayListenerDarwinRequiresRootGatewayProcess(t *testing.T) {
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
	own := darwinPCBFixture{
		local: client, remote: server, uid: uint32(os.Getuid()), lastPID: int32(os.Getpid()), state: darwinTCPSEstablish,
	}
	rootProcesses := map[int32]bool{4242: true, 4343: true}
	for _, tc := range []struct {
		name    string
		server  darwinPCBFixture
		wantErr string
	}{
		{name: "root gateway", server: darwinPCBFixture{uid: 0, lastPID: 4242}},
		{name: "root gateway with root delegate", server: darwinPCBFixture{uid: 0, lastPID: 4242, effectivePID: 4343}},
		{name: "unprivileged listener", server: darwinPCBFixture{uid: 501, lastPID: 4242}, wantErr: "owned by uid 501"},
		{name: "launchd-held socket", server: darwinPCBFixture{uid: 0, lastPID: 1}, wantErr: "held by pid 1"},
		{name: "unknown last pid", server: darwinPCBFixture{uid: 0, lastPID: 0}, wantErr: "held by pid 0"},
		{name: "served by a user process", server: darwinPCBFixture{uid: 0, lastPID: 9000}, wantErr: "process 9000"},
		{name: "delegated to a user process", server: darwinPCBFixture{uid: 0, lastPID: 4242, effectivePID: 9000}, wantErr: "delegate 9000"},
		{name: "delegated to launchd", server: darwinPCBFixture{uid: 0, lastPID: 4242, effectivePID: 1}, wantErr: "delegated to pid 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := tc.server
			record.local, record.remote, record.state = server, client, darwinTCPSEstablish
			list := buildDarwinPCBList(own, record)
			previousList, previousRoot := managedDarwinPCBList, managedDarwinProcessRoot
			managedDarwinPCBList = func() ([]byte, error) { return list, nil }
			managedDarwinProcessRoot = func(pid int32) error {
				if rootProcesses[pid] {
					return nil
				}
				return errors.New("process runs as uid 501 (real 501), want root")
			}
			defer func() { managedDarwinPCBList, managedDarwinProcessRoot = previousList, previousRoot }()

			err := verifyManagedGatewayListener(conn)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("verify = %v, want trusted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("verify = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestDarwinPCBListReportsLiveConnectionOwner reads the running kernel's
// table: the server side of a connection to a listener this process owns
// must read back as this process's uid and pid.
func TestDarwinPCBListReportsLiveConnectionOwner(t *testing.T) {
	listener := listenManagedUnixTransport(t)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client, server, err := managedConnEndpoints(conn)
	if err != nil {
		t.Fatal(err)
	}
	var record darwinTCPRecord
	for attempt := 0; attempt < 20; attempt++ {
		var list []byte
		list, err = readDarwinTCPPCBList()
		if err != nil {
			t.Fatal(err)
		}
		record, err = findDarwinServerSocket(list, client, server, uint32(os.Getuid()), int32(os.Getpid()))
		if !errors.Is(err, errManagedListenerPending) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if record.uid != uint32(os.Getuid()) || record.lastPID != int32(os.Getpid()) {
		t.Fatalf("server socket owner uid=%d pid=%d, want uid=%d pid=%d",
			record.uid, record.lastPID, os.Getuid(), os.Getpid())
	}
	select {
	case server := <-accepted:
		_ = server.Close()
	case <-time.After(time.Second):
	}
}

func TestDarwinProcessIsRoot(t *testing.T) {
	if err := darwinProcessIsRoot(1); err != nil {
		t.Fatalf("launchd credentials: %v", err)
	}
	if os.Geteuid() != 0 {
		if err := darwinProcessIsRoot(int32(os.Getpid())); err == nil {
			t.Fatal("unprivileged test process reported as root")
		}
	}
	if err := darwinProcessIsRoot(0x7ffffff0); err == nil {
		t.Fatal("nonexistent process reported as root")
	}
}

// TestVerifyManagedGatewayListenerDarwinLaunchdHeldSocket connects to a
// launchd-held listener when one exists on the host (Remote Login's sshd
// socket). launchd creates such sockets with root credentials on behalf of
// a job, so root socket ownership alone must not be accepted.
func TestVerifyManagedGatewayListenerDarwinLaunchdHeldSocket(t *testing.T) {
	conn, err := net.DialTimeout("tcp4", "127.0.0.1:22", time.Second)
	if err != nil {
		t.Skip("no local launchd-held listener on 127.0.0.1:22")
	}
	defer conn.Close()
	err = verifyManagedGatewayConn(t.Context(), conn)
	if err == nil {
		t.Skip("127.0.0.1:22 is served directly by a root process")
	}
	if !strings.Contains(err.Error(), "held by pid 1") && !strings.Contains(err.Error(), "process") {
		t.Fatalf("launchd-held listener error = %v", err)
	}
}
