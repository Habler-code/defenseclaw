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

// parseDarwinNetstat feeds table to _defenseclaw_darwin_listener_pids for
// port 18970 and returns the pids it printed and whether it exited 0.
func parseDarwinNetstat(t *testing.T, table string) (string, bool) {
	t.Helper()
	return runHardeningShell(t, `set -o pipefail; printf '%s' "$1" | _defenseclaw_darwin_listener_pids 18970 | tr '\n' ' '`, table)
}

// darwin26Row is one socket as `netstat -anv -p tcp` prints it from macOS 26
// (network_cmds 726 and later): a single "process:pid" column replaces the
// separate pid and epid columns.
type darwin26Row struct {
	proto, local, foreign, state, name string
	pid                                int
}

// darwin26Netstat renders rows with the printf formats of network_cmds-741
// (netstat.tproj inet.c protopr and main.c print_socket_stats_*) for -anv.
// That release prints the header's address columns 45 wide and the rows'
// 22 wide; only the fields matter to the parser.
func darwin26Netstat(rows ...darwin26Row) string {
	var b strings.Builder
	b.WriteString("Active Internet connections (including servers)\n")
	fmt.Fprintf(&b, "%-5.5s %-6.6s %-6.6s  ", "Proto", "Recv-Q", "Send-Q")
	fmt.Fprintf(&b, "%-45.45s %-45.45s ", "Local Address", "Foreign Address")
	fmt.Fprintf(&b, "%-11.11s", "(state)")
	fmt.Fprintf(&b, " %12.12s %12.12s", "rxbytes", "txbytes")
	fmt.Fprintf(&b, " %7.7s %7.7s %16s:%-6s", "rhiwat", "shiwat", "process", "pid")
	fmt.Fprintf(&b, " %5.5s %8.8s %16.16s %8.8s %8.8s %6s %6s %5s\n",
		"state", "options", "gencnt", "flags", "flags1", "usecnt", "rtncnt", "fltrs")
	return b.String() + darwin26Rows(rows...)
}

func darwin26Rows(rows ...darwin26Row) string {
	var b strings.Builder
	for i, row := range rows {
		version := row.proto[3:]
		if len(version) == 1 {
			version += " "
		}
		fmt.Fprintf(&b, "%-3.3s%-2.2s %6d %6d  ", "tcp", version, 0, 0)
		fmt.Fprintf(&b, "%-22.22s %-22.22s ", row.local, row.foreign)
		fmt.Fprintf(&b, "%-11s", row.state)
		fmt.Fprintf(&b, " %12d %12d", 0, 0)
		fmt.Fprintf(&b, " %7d %7d %16s:%-6d", 1048576, 1048576, row.name, row.pid)
		fmt.Fprintf(&b, " %05x %08x %016x %08x %08x %6d %6d %06x\n",
			0x100, 6, 0x10cb7+i, 0, 0x900, 1, 0, 0)
	}
	return b.String()
}

func TestHookListenerCheckParsesDarwinNetstat(t *testing.T) {
	// macOS 15 and earlier: separate pid and epid columns.
	const netstat15 = `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat    pid   epid state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
tcp4       0      0  127.0.0.1.18970        *.*                    LISTEN                 0            0 1048576 1048576    501      0 00000 00000006 0000000000010cb7 00000000 00000900      1      0 000000
tcp46      0      0  *.18970                *.*                    LISTEN                 0            0 1048576 1048576    777    888 00000 00000006 0000000000010cb8 00000000 00000900      1      0 000000
tcp6       0      0  ::1.18970              *.*                    LISTEN                 0            0 1048576 1048576      1      0 00000 00000006 0000000000010cb9 00000000 00000900      1      0 000000
tcp4       0      0  127.0.0.1.18970        127.0.0.1.50000        ESTABLISHED            0            0 1048576 1048576    502      0 00000 00000006 0000000000010cba 00000000 00000900      1      0 000000
tcp4       0      0  127.0.0.1.18971        *.*                    LISTEN                 0            0 1048576 1048576    503      0 00000 00000006 0000000000010cbb 00000000 00000900      1      0 000000
tcp4       0      0  10.0.0.1.18970         *.*                    LISTEN                 0            0 1048576 1048576    504      0 00000 00000006 0000000000010cbc 00000000 00000900      1      0 000000
`
	out, ok := parseDarwinNetstat(t, netstat15)
	if !ok {
		t.Fatal("macOS 15 netstat parse failed")
	}
	if got, want := out, "501 777 888 1"; got != want {
		t.Fatalf("macOS 15 listener pids = %q, want %q", got, want)
	}
	if _, ok := parseDarwinNetstat(t, "tcp4 0 0 127.0.0.1.18970 *.* LISTEN 0 0 1 1 501 0\n"); ok {
		t.Fatal("netstat output without a pid column was accepted")
	}
	header15 := strings.SplitAfterN(netstat15, "\n", 3)
	colon15 := header15[0] + header15[1] +
		"tcp4       0      0  127.0.0.1.18970        *.*                    LISTEN                 0            0 1048576 1048576  x:501      0 00000 00000006 0000000000010cb7 00000000 00000900      1      0 000000\n"
	if out, ok := parseDarwinNetstat(t, colon15); ok {
		t.Fatalf("macOS 15 pid column with a colon was accepted: %q", out)
	}

	// macOS 26: one "process:pid" column. Names may be empty, contain
	// colons, or contain spaces on sockets that are not the gateway port.
	netstat26 := darwin26Netstat(
		darwin26Row{"tcp4", "127.0.0.1.18970", "*.*", "LISTEN", "defenseclaw-gateway", 7970},
		darwin26Row{"tcp46", "*.18970", "*.*", "LISTEN", "", 7971},
		darwin26Row{"tcp6", "::1.18970", "*.*", "LISTEN", "a:b:12", 1},
		darwin26Row{"tcp4", "127.0.0.1.18970", "127.0.0.1.50000", "ESTABLISHED", "Code Helper (Renderer)", 502},
		darwin26Row{"tcp4", "127.0.0.1.18971", "*.*", "LISTEN", "Google Chrome He", 503},
		darwin26Row{"tcp4", "10.0.0.1.18970", "*.*", "LISTEN", "python3", 504},
	)
	out, ok = parseDarwinNetstat(t, netstat26)
	if !ok {
		t.Fatalf("macOS 26 netstat parse failed:\n%s", netstat26)
	}
	if got, want := out, "7970 7971 1"; got != want {
		t.Fatalf("macOS 26 listener pids = %q, want %q", got, want)
	}

	// Any local user names the process that holds a socket. A gateway-port
	// row whose name shifts or splits the row must make the lookup fail
	// (exit 3, "cannot verify"), never yield a pid from a forged field.
	gateway := func(name string, pid int) darwin26Row {
		return darwin26Row{"tcp4", "127.0.0.1.18970", "*.*", "LISTEN", name, pid}
	}
	for label, table := range map[string]string{
		// "x:345 evil" puts pid 345 where a parser counting from the start
		// of the row reads the pid.
		"space in name": darwin26Netstat(gateway("defenseclaw-gateway", 7970), gateway("x:345 evil", 4242)),
		// The first line keeps the real prefix, then a forged pid field and
		// eight forged socket fields: the field count matches and only the
		// column formats give it away. The rest of the row becomes a line
		// that does not start with a protocol.
		"newline-split row":       darwin26Netstat(gateway("x:345 0 0 0 0 0 0 0 0\nq", 4242)),
		"newline-split short row": darwin26Netstat(gateway("x\ntcp4", 4242)),
		// Another socket's name (29 bytes) starts a gateway-port LISTEN
		// line; the eight trailing fields it inherits leave it short.
		"newline-forged gateway row": darwin26Netstat(
			darwin26Row{"tcp4", "127.0.0.1.50001", "127.0.0.1.443", "ESTABLISHED", "\ntcp4 0 0 *.18970 *.* LISTEN ", 4242},
		),
		"header without trailing columns": "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state) process:pid\n" +
			"tcp4 0 0 127.0.0.1.18970 *.* LISTEN defenseclaw:7970\n",
	} {
		if out, ok := parseDarwinNetstat(t, table); ok {
			t.Fatalf("%s: lookup succeeded with pids %q, want refusal", label, out)
		}
	}
	for label, row := range map[string]string{
		"non-numeric pid": "tcp4 0 0 127.0.0.1.18970 *.* LISTEN 0 0 1048576 1048576 gw:12x 00100 00000006 0000000000010cb7 00000000 00000900 1 0 000000\n",
		"empty pid":       "tcp4 0 0 127.0.0.1.18970 *.* LISTEN 0 0 1048576 1048576 gw: 00100 00000006 0000000000010cb7 00000000 00000900 1 0 000000\n",
		"short gencnt":    "tcp4 0 0 127.0.0.1.18970 *.* LISTEN 0 0 1048576 1048576 gw:7970 00100 00000006 10cb7 00000000 00000900 1 0 000000\n",
		"non-hex options": "tcp4 0 0 127.0.0.1.18970 *.* LISTEN 0 0 1048576 1048576 gw:7970 00100 0000000g 0000000000010cb7 00000000 00000900 1 0 000000\n",
		"extra field":     "tcp4 0 0 127.0.0.1.18970 *.* LISTEN 0 0 1048576 1048576 x gw:7970 00100 00000006 0000000000010cb7 00000000 00000900 1 0 000000\n",
	} {
		if out, ok := parseDarwinNetstat(t, darwin26Netstat()+row); ok {
			t.Fatalf("%s: lookup succeeded with pids %q, want refusal", label, out)
		}
	}

	// Only the first header sets the layout: a later "Proto" line, such as
	// one a process name starts, cannot move the pid column.
	injected := darwin26Netstat(
		darwin26Row{"tcp4", "127.0.0.1.50001", "127.0.0.1.443", "ESTABLISHED", "q\nProto pid", 4242},
	) + "Proto a b c d e f pid g state options gencnt flags flags1 usecnt rtncnt fltrs\n" +
		darwin26Rows(gateway("defenseclaw-gateway", 7970))
	out, ok = parseDarwinNetstat(t, injected)
	if !ok || out != "7970" {
		t.Fatalf("injected header: pids %q ok %v, want 7970", out, ok)
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
	port := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
	// The live socket table must show this listener, so the acceptance
	// below is not the "nothing listening" case of a table it misread.
	lookup, want := `_defenseclaw_listener_uids_linux "$1"`, fmt.Sprint(os.Getuid())
	if runtime.GOOS == "darwin" {
		lookup, want = `set -o pipefail; netstat -anv -p tcp | _defenseclaw_darwin_listener_pids "$1"`, fmt.Sprint(os.Getpid())
	}
	if out, ok := runHardeningShell(t, lookup, port); !ok || out != want {
		t.Fatalf("live listener lookup for port %s = %q ok %v, want %q", port, out, ok, want)
	}
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
