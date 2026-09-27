//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func procAddr(ip net.IP, port int) string {
	return fmt.Sprintf("%08X:%04X", binary.NativeEndian.Uint32(ip.To4()), port)
}

func TestProcNetTCPOwnerUID(t *testing.T) {
	loop := net.IPv4(127, 0, 0, 1).To4()
	server := tcpTuple{localIP: loop, localPort: 18970, remoteIP: loop, remotePort: 50000}
	fixture := strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
		"   0: " + procAddr(loop, 18970) + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000   995        0 1 1 0000000000000000 100 0 0 10 0",
		"   1: " + procAddr(loop, 50000) + " " + procAddr(loop, 18970) + " 01 00000000:00000000 00:00000000 00000000  1000        0 2 1 0000000000000000 20 4 30 10 -1",
		"   2: " + procAddr(loop, 18970) + " " + procAddr(loop, 50000) + " 01 00000000:00000000 00:00000000 00000000   995        0 3 1 0000000000000000 20 4 30 10 -1",
	}, "\n")
	uid, err := procNetTCPOwnerUID(strings.NewReader(fixture), server)
	if err != nil || uid != 995 {
		t.Fatalf("owner = %d %v, want 995", uid, err)
	}
	if _, err := procNetTCPOwnerUID(strings.NewReader(fixture[:40]), server); err == nil {
		t.Fatal("truncated table must not yield an owner")
	}
	other := server
	other.remotePort = 1
	if _, err := procNetTCPOwnerUID(strings.NewReader(fixture), other); err == nil {
		t.Fatal("a non-matching tuple must not yield an owner")
	}
	if _, _, err := parseProcNetAddr("00000000000000000000000001000000:4A1A"); err == nil {
		t.Fatal("IPv6 rows are not accepted for the IPv4 lookup")
	}
}

func TestParseInetDiagReply(t *testing.T) {
	loop := net.IPv4(127, 0, 0, 1).To4()
	tuple := tcpTuple{localIP: loop, localPort: 18970, remoteIP: loop, remotePort: 50000}
	message := make([]byte, unix.SizeofNlMsghdr+inetDiagMsgLen)
	binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], sockDiagByFamily)
	body := message[unix.SizeofNlMsghdr:]
	body[0] = unix.AF_INET
	body[1] = tcpStateEstablished
	id := body[4:52]
	binary.BigEndian.PutUint16(id[0:2], 18970)
	binary.BigEndian.PutUint16(id[2:4], 50000)
	copy(id[4:8], loop)
	copy(id[20:24], loop)
	binary.NativeEndian.PutUint32(body[64:68], 995)
	uid, err := parseInetDiagReply(message, tuple)
	if err != nil || uid != 995 {
		t.Fatalf("uid = %d %v", uid, err)
	}
	if _, err := parseInetDiagReply(message[:20], tuple); err == nil {
		t.Fatal("truncated reply accepted")
	}
	wrong := tuple
	wrong.remotePort = 1
	if _, err := parseInetDiagReply(message, wrong); err == nil {
		t.Fatal("reply for another socket accepted")
	}
	// The kernel reports idiag_uid 0 for request and TIME_WAIT sockets
	// whoever owns the listener, so that 0 must never read as root.
	for _, state := range []byte{tcpStateSynRecv, 5 /* FIN_WAIT2 */, 6 /* TIME_WAIT */, 10 /* LISTEN */} {
		body[1] = state
		binary.NativeEndian.PutUint32(body[64:68], 0)
		if uid, err := parseInetDiagReply(message, tuple); !errors.Is(err, errInetDiagOwnerNotRecorded) {
			t.Fatalf("state %d: uid = %d err = %v, want errInetDiagOwnerNotRecorded", state, uid, err)
		}
	}
}

// TestProcNetTCPOwnerUIDStates: a request socket row carries the
// listener's uid and is accepted; a TIME_WAIT row prints uid 0 whoever
// listens and is refused.
func TestProcNetTCPOwnerUIDStates(t *testing.T) {
	loop := net.IPv4(127, 0, 0, 1).To4()
	server := tcpTuple{localIP: loop, localPort: 18970, remoteIP: loop, remotePort: 50000}
	row := func(state string, uid int) string {
		return strings.Join([]string{
			"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
			fmt.Sprintf("   0: %s %s %s 00000000:00000000 00:00000000 00000000 %5d        0 0 1 0000000000000000",
				procAddr(loop, 18970), procAddr(loop, 50000), state, uid),
		}, "\n")
	}
	if uid, err := procNetTCPOwnerUID(strings.NewReader(row("03", 1000)), server); err != nil || uid != 1000 {
		t.Fatalf("SYN_RECV row: owner = %d %v, want the listener uid 1000", uid, err)
	}
	for _, state := range []string{"06", "05", "0A", "08"} {
		if uid, err := procNetTCPOwnerUID(strings.NewReader(row(state, 0)), server); err == nil {
			t.Fatalf("state %s row accepted with owner %d", state, uid)
		}
	}
	if _, err := procNetTCPOwnerUID(strings.NewReader(row("zz", 0)), server); err == nil {
		t.Fatal("an unparsable state was accepted")
	}
}

// TestTCPListenerOwnerUIDDeferredAccept: a listener with TCP_DEFER_ACCEPT
// keeps the server side of a connected client as a request socket, for which
// sock_diag reports uid 0. The owner must still resolve to the account that
// holds the listener, never to root.
func TestTCPListenerOwnerUIDDeferredAccept(t *testing.T) {
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_DEFER_ACCEPT, 30)
		}); err != nil {
			return err
		}
		return sockErr
	}}
	listener, err := config.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	local := client.LocalAddr().(*net.TCPAddr)
	remote := client.RemoteAddr().(*net.TCPAddr)
	server := tcpTuple{
		localIP: remote.IP.To4(), localPort: remote.Port,
		remoteIP: local.IP.To4(), remotePort: local.Port,
	}
	if uid, err := inetDiagOwnerUID(server); err == nil {
		if uid != os.Getuid() {
			t.Fatalf("sock_diag accepted owner uid %d for a deferred-accept server socket, want %d or an error", uid, os.Getuid())
		}
	} else if !errors.Is(err, errInetDiagOwnerNotRecorded) {
		t.Logf("sock_diag lookup: %v", err)
	}
	uid, err := tcpListenerOwnerUID(client)
	if err != nil {
		t.Fatal(err)
	}
	if uid != os.Getuid() {
		t.Fatalf("owner uid = %d, want the listener's uid %d", uid, os.Getuid())
	}
}

// TestTCPListenerOwnerUIDLive asks the running kernel who owns the server
// side of a real loopback connection.
func TestTCPListenerOwnerUIDLive(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()
	uid, err := tcpListenerOwnerUID(client)
	if err != nil {
		t.Fatal(err)
	}
	if uid != os.Getuid() {
		t.Fatalf("owner uid = %d, want %d", uid, os.Getuid())
	}
	local := client.LocalAddr().(*net.TCPAddr)
	remote := client.RemoteAddr().(*net.TCPAddr)
	diagUID, diagErr := inetDiagOwnerUID(tcpTuple{
		localIP: remote.IP.To4(), localPort: remote.Port,
		remoteIP: local.IP.To4(), remotePort: local.Port,
	})
	if diagErr != nil {
		t.Fatalf("NETLINK_SOCK_DIAG exact lookup failed: %v", diagErr)
	}
	if diagUID != os.Getuid() {
		t.Fatalf("sock_diag owner uid = %d, want %d", diagUID, os.Getuid())
	}
}
