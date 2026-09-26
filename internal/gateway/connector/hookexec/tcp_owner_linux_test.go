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
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
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
