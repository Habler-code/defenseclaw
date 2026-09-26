// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// linuxManagedServiceAccount is the packaged account the managed gateway
// unit runs as (packaging/systemd/defenseclaw-gateway.service). The hook
// deliberately does not read DEFENSECLAW_UNIX_SERVICE_ACCOUNT: hooks inherit
// the agent's environment, which project-level agent settings can populate,
// so an inherited value must not widen the set of trusted listener owners.
const linuxManagedServiceAccount = "defenseclaw"

var (
	managedLinuxSocketTable  = readLinuxTCPSocketTable
	managedLinuxServiceUID   = lookupLinuxManagedServiceUID
	managedLinuxProcNetFiles = []string{"/proc/net/tcp", "/proc/net/tcp6"}
	managedLinuxUIDMapPath   = "/proc/self/uid_map"
)

const (
	linuxTCPEstablished = 0x01 // TCP_ESTABLISHED
	linuxTCPSynRecv     = 0x03 // TCP_SYN_RECV
	linuxTCPListen      = 0x0A // TCP_LISTEN
	procNetTCPMaxBytes  = 32 << 20
)

// linuxTCPSocketRow is one IPv4 (or IPv4-mapped / unspecified IPv6) row of
// /proc/net/tcp{,6}.
type linuxTCPSocketRow struct {
	local, remote managedIPv4Endpoint
	// wildcard marks a local address of 0.0.0.0 or :: (the latter is a
	// dual-stack listener that can receive IPv4 connections).
	wildcard bool
	state    uint8
	uid      uint32
	inode    uint64
}

// verifyManagedGatewayListener requires the kernel records for this
// connection to belong to root or the packaged gateway service account:
//
//   - every listening socket that could have received the connection (an
//     exact 127.0.0.1 listener takes precedence over wildcard listeners).
//     Linux reports a connection that is still queued for accept() with
//     uid 0, so the listener's owner is what identifies the server;
//   - the server side of the exact 4-tuple once a process has accepted it
//     (it then carries the accepting process's uid).
func verifyManagedGatewayListener(conn net.Conn) error {
	// /proc/net/tcp reports owners in the reader's user namespace, where an
	// unprivileged user can appear as uid 0. Only the initial namespace
	// reports real owners.
	if err := requireInitialLinuxUserNamespace(managedLinuxUIDMapPath); err != nil {
		return err
	}
	client, server, err := managedConnEndpoints(conn)
	if err != nil {
		return err
	}
	rows, err := managedLinuxSocketTable()
	if err != nil {
		return err
	}
	trusted := func(uid uint32) bool {
		if uid == 0 {
			return true
		}
		serviceUID, err := managedLinuxServiceUID()
		return err == nil && uid == serviceUID
	}
	return checkLinuxGatewaySockets(rows, client, server, trusted)
}

func checkLinuxGatewaySockets(
	rows []linuxTCPSocketRow,
	client managedIPv4Endpoint,
	server managedIPv4Endpoint,
	trusted func(uint32) bool,
) error {
	var (
		connections     []linuxTCPSocketRow
		exact, wildcard []linuxTCPSocketRow
	)
	for _, row := range rows {
		switch {
		case row.state == linuxTCPListen && row.local.port == server.port:
			if row.wildcard {
				wildcard = append(wildcard, row)
			} else if row.local.addr == server.addr {
				exact = append(exact, row)
			}
		case (row.state == linuxTCPEstablished || row.state == linuxTCPSynRecv) &&
			!row.wildcard && row.local == server && row.remote == client:
			connections = append(connections, row)
		}
	}
	switch len(connections) {
	case 0:
		return fmt.Errorf("%w: no socket for %s -> %s", errManagedListenerPending, server, client)
	case 1:
	default:
		return fmt.Errorf("%d sockets claim %s -> %s", len(connections), server, client)
	}
	connection := connections[0]
	// A connection still queued for accept() has no owning file (inode 0) and
	// is reported as uid 0; once accepted it carries the acceptor's uid.
	if connection.inode != 0 && !trusted(connection.uid) {
		return fmt.Errorf("gateway connection %s was accepted by uid %d", server, connection.uid)
	}
	listeners := exact
	if len(listeners) == 0 {
		listeners = wildcard
	}
	if len(listeners) == 0 {
		return fmt.Errorf("no listening socket for %s owns this connection", server)
	}
	for _, listener := range listeners {
		if !trusted(listener.uid) {
			return fmt.Errorf(
				"gateway listener %s is owned by uid %d, want root or the %s service account",
				server,
				listener.uid,
				linuxManagedServiceAccount,
			)
		}
	}
	return nil
}

// requireInitialLinuxUserNamespace accepts only the identity mapping of the
// initial user namespace ("0 0 4294967295").
func requireInitialLinuxUserNamespace(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read user namespace map: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) != 3 || fields[0] != "0" || fields[1] != "0" || fields[2] != "4294967295" {
		return errors.New("hook runs in a nested user namespace; socket owners cannot be verified")
	}
	return nil
}

func lookupLinuxManagedServiceUID() (uint32, error) {
	account, err := user.Lookup(linuxManagedServiceAccount)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return 0, err
	}
	if uid == 0 {
		return 0, errors.New("service account resolves to uid 0")
	}
	return uint32(uid), nil
}

// readLinuxTCPSocketTable reads the caller's network namespace socket
// tables. /proc/net/tcp is required; /proc/net/tcp6 is optional (IPv6 may
// be disabled).
func readLinuxTCPSocketTable() ([]linuxTCPSocketRow, error) {
	var rows []linuxTCPSocketRow
	for index, path := range managedLinuxProcNetFiles {
		file, err := os.Open(path)
		if err != nil {
			if index == 0 {
				return nil, fmt.Errorf("open %s: %w", path, err)
			}
			continue
		}
		parsed, err := parseProcNetTCP(io.LimitReader(file, procNetTCPMaxBytes))
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		rows = append(rows, parsed...)
	}
	return rows, nil
}

// parseProcNetTCP returns the rows that can carry an IPv4 loopback
// connection: IPv4 rows, IPv4-mapped IPv6 rows, and unspecified (::)
// IPv6 listeners. Other IPv6 rows are skipped.
func parseProcNetTCP(r io.Reader) ([]linuxTCPSocketRow, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 4096)
	var rows []linuxTCPSocketRow
	for line := 0; scanner.Scan(); line++ {
		fields := strings.Fields(scanner.Text())
		if line == 0 && len(fields) > 1 && fields[1] == "local_address" {
			continue
		}
		if len(fields) < 10 {
			continue
		}
		local, localWildcard, err := parseProcNetEndpoint(fields[1])
		if err != nil {
			continue
		}
		remote, _, err := parseProcNetEndpoint(fields[2])
		if err != nil {
			continue
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("parse socket state %q: %w", fields[3], err)
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse socket uid %q: %w", fields[7], err)
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse socket inode %q: %w", fields[9], err)
		}
		rows = append(rows, linuxTCPSocketRow{
			local:    local,
			remote:   remote,
			wildcard: localWildcard,
			state:    uint8(state),
			uid:      uint32(uid),
			inode:    inode,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

// parseProcNetEndpoint decodes "0100007F:4A1A" (IPv4) or the 32-digit IPv6
// form. Each 8-digit group is a host-order rendering of a network-order
// 32-bit word; the port is host-order hex. The boolean reports an
// unspecified address (0.0.0.0 or ::).
func parseProcNetEndpoint(value string) (managedIPv4Endpoint, bool, error) {
	host, rawPort, ok := strings.Cut(value, ":")
	if !ok || (len(host) != 8 && len(host) != 32) {
		return managedIPv4Endpoint{}, false, fmt.Errorf("unsupported address %q", value)
	}
	raw := make([]byte, 0, 16)
	for i := 0; i < len(host); i += 8 {
		word, err := strconv.ParseUint(host[i:i+8], 16, 32)
		if err != nil {
			return managedIPv4Endpoint{}, false, err
		}
		raw = binary.NativeEndian.AppendUint32(raw, uint32(word))
	}
	port, err := strconv.ParseUint(rawPort, 16, 16)
	if err != nil {
		return managedIPv4Endpoint{}, false, err
	}
	ip := net.IP(raw)
	var endpoint managedIPv4Endpoint
	endpoint.port = uint16(port)
	if ip.IsUnspecified() {
		return endpoint, true, nil
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return managedIPv4Endpoint{}, false, fmt.Errorf("address %q is not IPv4", value)
	}
	copy(endpoint.addr[:], ip4)
	return endpoint, false, nil
}
