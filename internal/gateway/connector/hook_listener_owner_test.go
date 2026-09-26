// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package connector

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runHardeningShell sources hooks/_hardening.sh and runs script with the
// system PATH; it returns trimmed stdout and whether the script exited 0.
func runHardeningShell(t *testing.T, script string, args ...string) (string, bool) {
	t.Helper()
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	cmd := exec.Command("/bin/bash", append([]string{"-c", `. "$0"; ` + script, helperPath}, args...)...)
	cmd.Env = []string{"HOME=" + dir, "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err == nil
}

func TestHookListenerCheckParsesLinuxSocketTables(t *testing.T) {
	const table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:4A1A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 11 1 0 100 0 0 10 0
   1: 00000000:4A1A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1002        0 12 1 0 100 0 0 10 0
   2: 0100007F:4A1A 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1003        0 13 1 0 100 0 0 10 0
   3: 0100007F:4A1B 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1004        0 14 1 0 100 0 0 10 0
   4: 0A000001:4A1A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1005        0 15 1 0 100 0 0 10 0
`
	const table6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:4A1A 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1006        0 16 1 0 100 0 0 10 0
   1: 00000000000000000000000001000000:4A1A 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1007        0 17 1 0 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:4A1A 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1008        0 18 1 0 100 0 0 10 0
   3: 20010DB8000000000000000000000001:4A1A 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1009        0 19 1 0 100 0 0 10 0
`
	dir := t.TempDir()
	tcp, tcp6 := filepath.Join(dir, "tcp"), filepath.Join(dir, "tcp6")
	if err := os.WriteFile(tcp, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tcp6, []byte(table6), 0o600); err != nil {
		t.Fatal(err)
	}
	out, ok := runHardeningShell(t, `_defenseclaw_listener_uids_linux "$1" "$2" "$3" | tr '\n' ' '`, "18970", tcp, tcp6)
	if !ok {
		t.Fatal("listener table parse failed")
	}
	// Loopback and wildcard listeners on 18970 only: not the established
	// connection, not port 18971, not 10.0.0.1, not a global IPv6 address.
	if got, want := out, "1001 1002 1006 1007 1008"; got != want {
		t.Fatalf("listener owners = %q, want %q", got, want)
	}
}

func TestHookListenerCheckParsesDarwinNetstat(t *testing.T) {
	const netstat = `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat    pid   epid state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
tcp4       0      0  127.0.0.1.18970        *.*                    LISTEN                 0            0 1048576 1048576    501      0 00000 00000006 0000000000010cb7 00000000 00000900      1      0 000000
tcp46      0      0  *.18970                *.*                    LISTEN                 0            0 1048576 1048576    777    888 00000 00000006 0000000000010cb8 00000000 00000900      1      0 000000
tcp6       0      0  ::1.18970              *.*                    LISTEN                 0            0 1048576 1048576      1      0 00000 00000006 0000000000010cb9 00000000 00000900      1      0 000000
tcp4       0      0  127.0.0.1.18970        127.0.0.1.50000        ESTABLISHED            0            0 1048576 1048576    502      0 00000 00000006 0000000000010cba 00000000 00000900      1      0 000000
tcp4       0      0  127.0.0.1.18971        *.*                    LISTEN                 0            0 1048576 1048576    503      0 00000 00000006 0000000000010cbb 00000000 00000900      1      0 000000
tcp4       0      0  10.0.0.1.18970         *.*                    LISTEN                 0            0 1048576 1048576    504      0 00000 00000006 0000000000010cbc 00000000 00000900      1      0 000000
`
	out, ok := runHardeningShell(t, `printf '%s' "$1" | _defenseclaw_darwin_listener_pids 18970 | tr '\n' ' '`, netstat)
	if !ok {
		t.Fatal("netstat parse failed")
	}
	if got, want := out, "501 777 888 1"; got != want {
		t.Fatalf("listener pids = %q, want %q", got, want)
	}
	if _, ok := runHardeningShell(t, `printf 'tcp4 0 0 127.0.0.1.18970 *.* LISTEN 0 0 1 1 501 0\n' | _defenseclaw_darwin_listener_pids 18970`); ok {
		t.Fatal("netstat output without a pid column was accepted")
	}
}

func TestHookListenerCheckScope(t *testing.T) {
	for _, addr := range []string{"gateway.example:18970", "10.0.0.5:18970", "noport"} {
		if _, ok := runHardeningShell(t, `defenseclaw_verify_gateway_listener "$1"`, addr); !ok {
			t.Fatalf("out-of-scope address %q was refused", addr)
		}
	}
	if out, ok := runHardeningShell(t, `defenseclaw_verify_gateway_listener "$1" || { printf '%s' "$DEFENSECLAW_LISTENER_REASON"; exit 1; }`, "127.0.0.1:abc"); ok || !strings.Contains(out, "numeric port") {
		t.Fatalf("non-numeric port = ok %v reason %q", ok, out)
	}
}

// TestHookListenerCheckAcceptsOwnListener binds a real loopback listener as
// the test account; the hook check must accept it, and must also accept a
// port nobody listens on (curl then fails to connect).
func TestHookListenerCheckAcceptsOwnListener(t *testing.T) {
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("netstat"); err != nil {
			t.Skip("netstat is required")
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if out, ok := runHardeningShell(t, `defenseclaw_verify_gateway_listener "$1" || { printf '%s' "$DEFENSECLAW_LISTENER_REASON"; exit 1; }`, addr); !ok {
		t.Fatalf("own listener %s refused: %s", addr, out)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if out, ok := runHardeningShell(t, `defenseclaw_verify_gateway_listener "$1" || { printf '%s' "$DEFENSECLAW_LISTENER_REASON"; exit 1; }`, addr); !ok {
		t.Fatalf("closed port %s refused: %s", addr, out)
	}
}

// TestHookListenerCheckRefusesForeignOwner runs the check as a different
// account than the listener's owner. It needs root to create the second
// account's process and is run on the disposable test hosts
// (DEFENSECLAW_TEST_FOREIGN_UID and DEFENSECLAW_TEST_OTHER_UID name two
// unprivileged uids).
func TestHookListenerCheckRefusesForeignOwner(t *testing.T) {
	raw, other := os.Getenv("DEFENSECLAW_TEST_FOREIGN_UID"), os.Getenv("DEFENSECLAW_TEST_OTHER_UID")
	if raw == "" || other == "" || os.Geteuid() != 0 {
		t.Skip("requires root, DEFENSECLAW_TEST_FOREIGN_UID and DEFENSECLAW_TEST_OTHER_UID")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Root owns this listener, which every account trusts. The foreign
	// account then holds a second port: its owner accepts it and a second
	// unprivileged account must refuse it.
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	// t.TempDir's parent is private to root; the checks run as other uids.
	dir, err := os.MkdirTemp("", "dc-listener-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	helperPath := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o755); err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	holder := exec.Command("/usr/bin/sudo", "-u", "#"+raw, "/usr/bin/python3", "-c",
		fmt.Sprintf(`import socket,time
s=socket.socket(); s.bind(("127.0.0.1",%d)); s.listen(1); print("up",flush=True); time.sleep(20)`, port+1))
	stdout, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Skipf("start foreign listener: %v", err)
	}
	defer func() { _ = holder.Process.Kill(); _ = holder.Wait() }()
	buf := make([]byte, 3)
	if _, err := stdout.Read(buf); err != nil {
		t.Skipf("foreign listener did not start: %v", err)
	}
	check := func(uid string, target int) (string, bool) {
		cmd := exec.Command("/usr/bin/sudo", "-u", "#"+uid, "/bin/bash", "-c",
			`. "$0"; defenseclaw_verify_gateway_listener "$1" || { printf '%s' "$DEFENSECLAW_LISTENER_REASON"; exit 1; }`,
			helperPath, fmt.Sprintf("127.0.0.1:%d", target))
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err == nil
	}
	if out, ok := check(raw, port); !ok {
		t.Fatalf("root-owned listener refused for uid %s: %s", raw, out)
	}
	if out, ok := check(other, port+1); ok || !strings.Contains(out, "held by") {
		t.Fatalf("foreign listener check = ok %v reason %q, want refusal", ok, out)
	}
	if out, ok := check(raw, port+1); !ok {
		t.Fatalf("owner's own listener refused: %s", out)
	}
}
