// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// The macOS managed gateway is the root LaunchDaemon. The kernel's TCP PCB
// list (net.inet.tcp.pcblist_n, the source netstat(1) uses, readable without
// privilege) records, for the server side of this exact connection, the
// credential that created the listening socket (so_uid) and the last process
// that operated on it (so_last_pid). All three checks must pass:
//
//   - so_uid is 0: the listening socket was created with root credentials;
//   - so_last_pid is a live root process other than launchd (pid 1): a
//     socket that launchd opened for a per-user job carries launchd's root
//     credential but is served by that job, so it is refused;
//   - a delegated socket's effective pid, when present, is also root.
var (
	managedDarwinPCBList     = readDarwinTCPPCBList
	managedDarwinProcessRoot = darwinProcessIsRoot
)

func verifyManagedGatewayListener(conn net.Conn) error {
	client, server, err := managedConnEndpoints(conn)
	if err != nil {
		return err
	}
	list, err := managedDarwinPCBList()
	if err != nil {
		return fmt.Errorf("read TCP PCB list: %w", err)
	}
	record, err := findDarwinServerSocket(list, client, server, uint32(os.Getuid()), int32(os.Getpid()))
	if err != nil {
		return err
	}
	if record.uid != 0 {
		return fmt.Errorf("gateway listener %s is owned by uid %d, want root", server, record.uid)
	}
	if record.lastPID <= 1 {
		return fmt.Errorf("gateway listener %s is held by pid %d, not by the gateway service", server, record.lastPID)
	}
	if err := managedDarwinProcessRoot(record.lastPID); err != nil {
		return fmt.Errorf("gateway listener %s process %d: %w", server, record.lastPID, err)
	}
	if record.effectivePID != 0 && record.effectivePID != record.lastPID {
		if record.effectivePID <= 1 {
			return fmt.Errorf("gateway listener %s is delegated to pid %d", server, record.effectivePID)
		}
		if err := managedDarwinProcessRoot(record.effectivePID); err != nil {
			return fmt.Errorf("gateway listener %s delegate %d: %w", server, record.effectivePID, err)
		}
	}
	return nil
}

func darwinProcessIsRoot(pid int32) error {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		return fmt.Errorf("read process credentials: %w", err)
	}
	if info.Proc.P_pid != pid {
		return fmt.Errorf("process credentials name pid %d", info.Proc.P_pid)
	}
	const zombie = 5 // SZOMB
	if info.Proc.P_stat == zombie {
		return errors.New("process has exited")
	}
	if info.Eproc.Ucred.Uid != 0 || info.Eproc.Pcred.P_ruid != 0 {
		return fmt.Errorf(
			"process runs as uid %d (real %d), want root",
			info.Eproc.Ucred.Uid,
			info.Eproc.Pcred.P_ruid,
		)
	}
	return nil
}

const (
	maxDarwinPCBListBytes = 64 << 20

	// xgen_n kinds (bsd/sys/socketvar.h).
	darwinXSOSocket = 0x001
	darwinXSORcvBuf = 0x002
	darwinXSOSndBuf = 0x004
	darwinXSOStats  = 0x008
	darwinXSOInpcb  = 0x010
	darwinXSOTCPCB  = 0x020
	darwinXSOAllTCP = darwinXSOSocket | darwinXSORcvBuf | darwinXSOSndBuf |
		darwinXSOStats | darwinXSOInpcb | darwinXSOTCPCB

	// struct xinpcb_n (bsd/netinet/in_pcb.h, #pragma pack(4)).
	darwinInpcbFPort    = 16
	darwinInpcbLPort    = 18
	darwinInpcbVFlag    = 44
	darwinInpcbFAddr4   = 60 // inp_dependfaddr.inp46_foreign.ia46_addr4
	darwinInpcbLAddr4   = 76 // inp_dependladdr.inp46_local.ia46_addr4
	darwinInpcbMinLen   = 80
	darwinInpVFlagIPv4  = 0x1
	darwinSocketProto   = 36
	darwinSocketFamily  = 40
	darwinSocketUID     = 64
	darwinSocketLastPID = 68
	darwinSocketEPID    = 72
	darwinSocketMinLen  = 76
	darwinTCPCBState    = 36
	darwinTCPCBMinLen   = 40
	darwinTCPSEstablish = 4 // TCPS_ESTABLISHED
	darwinAFInet        = 2
	darwinAFInet6       = 30
	darwinIPProtoTCP    = 6
	darwinXinpgenMinLen = 24
)

type darwinTCPRecord struct {
	local, remote managedIPv4Endpoint
	ipv4          bool
	family        int32
	protocol      int32
	uid           uint32
	lastPID       int32
	effectivePID  int32
	state         int32
}

func readDarwinTCPPCBList() ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		buffer, err := unix.SysctlRaw("net.inet.tcp.pcblist_n")
		if err == nil {
			if len(buffer) > maxDarwinPCBListBytes {
				return nil, fmt.Errorf("TCP PCB list is %d bytes", len(buffer))
			}
			return buffer, nil
		}
		// ENOMEM: the table grew between the size probe and the read.
		if !errors.Is(err, unix.ENOMEM) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func roundUp64(value uint32) int {
	return int((uint64(value) + 7) &^ 7)
}

// parseDarwinTCPPCBList decodes the xinpgen-framed sequence of per-socket
// xgen_n records. Each socket contributes one record of every kind; a record
// is emitted once all six kinds for the current socket have been seen.
func parseDarwinTCPPCBList(buffer []byte) ([]darwinTCPRecord, error) {
	order := binary.LittleEndian
	if len(buffer) < darwinXinpgenMinLen {
		return nil, errors.New("TCP PCB list is truncated")
	}
	headerLen := order.Uint32(buffer[0:4])
	if headerLen < darwinXinpgenMinLen || int(headerLen) > len(buffer) {
		return nil, errors.New("TCP PCB list header is malformed")
	}
	var (
		records              []darwinTCPRecord
		inpcb, socket, tcpcb []byte
		seen                 uint32
		terminated           bool
	)
	offset := roundUp64(headerLen)
	for offset+8 <= len(buffer) {
		length := order.Uint32(buffer[offset : offset+4])
		kind := order.Uint32(buffer[offset+4 : offset+8])
		if length <= darwinXinpgenMinLen {
			terminated = true
			break
		}
		end := offset + int(length)
		if end > len(buffer) || end < offset {
			return nil, errors.New("TCP PCB list record is truncated")
		}
		item := buffer[offset:end]
		offset += roundUp64(length)
		switch kind {
		case darwinXSOInpcb:
			inpcb = item
		case darwinXSOSocket:
			socket = item
		case darwinXSOTCPCB:
			tcpcb = item
		case darwinXSORcvBuf, darwinXSOSndBuf, darwinXSOStats:
		default:
			// Kinds this parser does not consume (netstat ignores them too).
			continue
		}
		if seen&kind != 0 {
			return nil, fmt.Errorf("TCP PCB list repeats record kind %#x", kind)
		}
		seen |= kind
		if seen != darwinXSOAllTCP {
			continue
		}
		seen = 0
		if len(inpcb) < darwinInpcbMinLen || len(socket) < darwinSocketMinLen || len(tcpcb) < darwinTCPCBMinLen {
			return nil, errors.New("TCP PCB list record is shorter than the supported layout")
		}
		var record darwinTCPRecord
		record.remote.port = binary.BigEndian.Uint16(inpcb[darwinInpcbFPort:])
		record.local.port = binary.BigEndian.Uint16(inpcb[darwinInpcbLPort:])
		record.ipv4 = inpcb[darwinInpcbVFlag]&darwinInpVFlagIPv4 != 0
		copy(record.remote.addr[:], inpcb[darwinInpcbFAddr4:darwinInpcbFAddr4+4])
		copy(record.local.addr[:], inpcb[darwinInpcbLAddr4:darwinInpcbLAddr4+4])
		record.protocol = int32(order.Uint32(socket[darwinSocketProto:]))
		record.family = int32(order.Uint32(socket[darwinSocketFamily:]))
		record.uid = order.Uint32(socket[darwinSocketUID:])
		record.lastPID = int32(order.Uint32(socket[darwinSocketLastPID:]))
		record.effectivePID = int32(order.Uint32(socket[darwinSocketEPID:]))
		record.state = int32(order.Uint32(tcpcb[darwinTCPCBState:]))
		records = append(records, record)
	}
	if seen != 0 {
		return nil, errors.New("TCP PCB list ends inside a socket record")
	}
	if !terminated {
		return nil, errors.New("TCP PCB list is missing its trailer")
	}
	return records, nil
}

// findDarwinServerSocket returns the socket whose local endpoint is the
// client's remote endpoint and whose remote endpoint is the client's local
// endpoint, i.e. the server side of this exact connection. The caller's own
// client socket is located in the same snapshot and must read back as this
// process's uid and pid; that calibrates the private record layout, so an OS
// release that moves the credential fields fails closed instead of being
// misread.
func findDarwinServerSocket(
	buffer []byte,
	client managedIPv4Endpoint,
	server managedIPv4Endpoint,
	selfUID uint32,
	selfPID int32,
) (darwinTCPRecord, error) {
	records, err := parseDarwinTCPPCBList(buffer)
	if err != nil {
		return darwinTCPRecord{}, err
	}
	serverSide, err := uniqueDarwinSocket(records, server, client)
	if err != nil {
		return darwinTCPRecord{}, err
	}
	clientSide, err := uniqueDarwinSocket(records, client, server)
	if err != nil {
		return darwinTCPRecord{}, err
	}
	if clientSide.uid != selfUID || clientSide.lastPID != selfPID {
		return darwinTCPRecord{}, fmt.Errorf(
			"TCP PCB list layout is not supported (own socket reads uid %d pid %d)",
			clientSide.uid,
			clientSide.lastPID,
		)
	}
	if serverSide.state != darwinTCPSEstablish {
		return darwinTCPRecord{}, fmt.Errorf("%w: server socket state %d", errManagedListenerPending, serverSide.state)
	}
	return serverSide, nil
}

func uniqueDarwinSocket(
	records []darwinTCPRecord,
	local managedIPv4Endpoint,
	remote managedIPv4Endpoint,
) (darwinTCPRecord, error) {
	var (
		match darwinTCPRecord
		found int
	)
	for _, record := range records {
		if !record.ipv4 || record.local != local || record.remote != remote {
			continue
		}
		match = record
		found++
	}
	switch {
	case found == 0:
		return darwinTCPRecord{}, fmt.Errorf("%w: no socket for %s -> %s", errManagedListenerPending, local, remote)
	case found > 1:
		return darwinTCPRecord{}, fmt.Errorf("%d sockets claim %s -> %s", found, local, remote)
	}
	if match.protocol != darwinIPProtoTCP || (match.family != darwinAFInet && match.family != darwinAFInet6) {
		return darwinTCPRecord{}, fmt.Errorf(
			"TCP PCB list layout is not supported (family %d protocol %d)",
			match.family,
			match.protocol,
		)
	}
	return match, nil
}
