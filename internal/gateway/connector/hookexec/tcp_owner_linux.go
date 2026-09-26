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
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// tcpListenerOwnerUID returns the uid that owns the server side of conn:
// the socket whose local address is conn's remote address and whose remote
// address is conn's local address. The kernel records that owner from the
// listening socket's creator, so an impostor listener shows the impostor's
// uid. NETLINK_SOCK_DIAG answers unprivileged callers (it is what ss(8)
// uses); /proc/net/tcp is the bounded fallback.
func tcpListenerOwnerUID(conn net.Conn) (int, error) {
	local, localOK := conn.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := conn.RemoteAddr().(*net.TCPAddr)
	if !localOK || !remoteOK || local.IP.To4() == nil || remote.IP.To4() == nil {
		return 0, errors.New("connection is not IPv4 TCP")
	}
	// Server side: local = our remote, remote = our local.
	server := tcpTuple{
		localIP: remote.IP.To4(), localPort: remote.Port,
		remoteIP: local.IP.To4(), remotePort: local.Port,
	}
	if uid, err := inetDiagOwnerUID(server); err == nil {
		return uid, nil
	}
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return 0, fmt.Errorf("open /proc/net/tcp: %w", err)
	}
	defer file.Close()
	return procNetTCPOwnerUID(io.LimitReader(file, procNetTCPLimit), server)
}

type tcpTuple struct {
	localIP    net.IP
	localPort  int
	remoteIP   net.IP
	remotePort int
}

// procNetTCPLimit bounds the fallback read (a very busy host is still far
// below this; the netlink path is exact and preferred).
const procNetTCPLimit = 32 << 20

// procNetTCPOwnerUID parses /proc/net/tcp and returns the uid of the row
// whose local/remote endpoints equal tuple.
func procNetTCPOwnerUID(r io.Reader, tuple tcpTuple) (int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 4096)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false
			if strings.Contains(line, "local_address") {
				continue
			}
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		localIP, localPort, err := parseProcNetAddr(fields[1])
		if err != nil {
			continue
		}
		remoteIP, remotePort, err := parseProcNetAddr(fields[2])
		if err != nil {
			continue
		}
		if !localIP.Equal(tuple.localIP) || localPort != tuple.localPort ||
			!remoteIP.Equal(tuple.remoteIP) || remotePort != tuple.remotePort {
			continue
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse /proc/net/tcp uid %q: %w", fields[7], err)
		}
		return int(uid), nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read /proc/net/tcp: %w", err)
	}
	return 0, errors.New("server socket not found in /proc/net/tcp")
}

// parseProcNetAddr decodes "0100007F:4A1A": the IPv4 address is the kernel's
// __be32 printed as a host-order integer, the port is host-order hex.
func parseProcNetAddr(value string) (net.IP, int, error) {
	host, rawPort, ok := strings.Cut(value, ":")
	if !ok || len(host) != 8 {
		return nil, 0, fmt.Errorf("unsupported address %q", value)
	}
	raw, err := strconv.ParseUint(host, 16, 32)
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.ParseUint(rawPort, 16, 16)
	if err != nil {
		return nil, 0, err
	}
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, uint32(raw))
	return ip, int(port), nil
}

const (
	sockDiagByFamily = 20 // SOCK_DIAG_BY_FAMILY
	inetDiagReqV2Len = 56
	inetDiagMsgLen   = 72
)

// inetDiagOwnerUID asks the kernel for the exact socket through
// NETLINK_SOCK_DIAG. The request names the 4-tuple, so the reply is that
// one socket or nothing.
func inetDiagOwnerUID(tuple tcpTuple) (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	timeout := unix.Timeval{Sec: 1}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout)
	if err := unix.Sendto(fd, inetDiagRequest(tuple), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, err
	}
	buffer := make([]byte, 16<<10)
	n, _, err := unix.Recvfrom(fd, buffer, 0)
	if err != nil {
		return 0, err
	}
	return parseInetDiagReply(buffer[:n], tuple)
}

func inetDiagRequest(tuple tcpTuple) []byte {
	const headerLen = unix.SizeofNlMsghdr
	message := make([]byte, headerLen+inetDiagReqV2Len)
	binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], sockDiagByFamily)
	binary.NativeEndian.PutUint16(message[6:8], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(message[8:12], 1)
	request := message[headerLen:]
	request[0] = unix.AF_INET
	request[1] = unix.IPPROTO_TCP
	// idiag_states: every state (the server side of a live connection is
	// ESTABLISHED; the mask keeps the lookup exact by tuple only).
	binary.NativeEndian.PutUint32(request[4:8], 0xffffffff)
	id := request[8:]
	binary.BigEndian.PutUint16(id[0:2], uint16(tuple.localPort))
	binary.BigEndian.PutUint16(id[2:4], uint16(tuple.remotePort))
	copy(id[4:8], tuple.localIP.To4())
	copy(id[20:24], tuple.remoteIP.To4())
	// idiag_if = 0; idiag_cookie = INET_DIAG_NOCOOKIE.
	binary.NativeEndian.PutUint32(id[40:44], 0xffffffff)
	binary.NativeEndian.PutUint32(id[44:48], 0xffffffff)
	return message
}

// parseInetDiagReply extracts idiag_uid from the reply for tuple.
func parseInetDiagReply(data []byte, tuple tcpTuple) (int, error) {
	for len(data) >= unix.SizeofNlMsghdr {
		length := int(binary.NativeEndian.Uint32(data[0:4]))
		kind := binary.NativeEndian.Uint16(data[4:6])
		if length < unix.SizeofNlMsghdr || length > len(data) {
			return 0, errors.New("truncated netlink message")
		}
		body := data[unix.SizeofNlMsghdr:length]
		switch kind {
		case unix.NLMSG_ERROR:
			if len(body) >= 4 {
				if code := int32(binary.NativeEndian.Uint32(body[0:4])); code != 0 {
					return 0, fmt.Errorf("sock_diag error %d", -code)
				}
			}
			return 0, errors.New("sock_diag returned no socket")
		case unix.NLMSG_DONE:
			return 0, errors.New("sock_diag returned no socket")
		case sockDiagByFamily:
			if len(body) < inetDiagMsgLen {
				return 0, errors.New("truncated inet_diag message")
			}
			id := body[4:52]
			sport := int(binary.BigEndian.Uint16(id[0:2]))
			dport := int(binary.BigEndian.Uint16(id[2:4]))
			src := net.IP(id[4:8])
			dst := net.IP(id[20:24])
			if sport == tuple.localPort && dport == tuple.remotePort &&
				bytes.Equal(src.To4(), tuple.localIP.To4()) && bytes.Equal(dst.To4(), tuple.remoteIP.To4()) {
				return int(binary.NativeEndian.Uint32(body[64:68])), nil
			}
		}
		aligned := (length + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
		if aligned > len(data) {
			break
		}
		data = data[aligned:]
	}
	return 0, errors.New("sock_diag reply does not name the socket")
}
