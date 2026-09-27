#!/usr/bin/env bash
#
# Runs the enterprisehooks per-target worker tests that need root: the real
# setgroups/setgid/setuid drop and its checks, the worker process hardening,
# the Linux /proc/self/exe re-exec, repair races, deadlines and watch-path
# resolution. Those tests skip unless the test binary runs as root, so this
# builds the binary as the invoking user and runs it with sudo, with the
# invoking user as the repair target. A skipped test fails the run.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/dc-root-worker.XXXXXX")
trap 'rm -rf "$work"' EXIT
binary="$work/enterprisehooks.test"
log="$work/root-worker.log"

(cd "$repo_root" && go test -c -o "$binary" ./internal/enterprisehooks)

status=0
(
    cd "$repo_root/internal/enterprisehooks"
    sudo -n env DEFENSECLAW_TEST_TARGET_UID="$(id -u)" \
        "$binary" -test.run '^TestRootGuardian' -test.count=1 -test.v
) >"$log" 2>&1 || status=$?

grep -E -- '^(--- |ok|PASS|FAIL)' "$log" || true
if [ "$status" -ne 0 ]; then
    tail -n 80 "$log"
    exit "$status"
fi
if grep -q -- '--- SKIP' "$log"; then
    grep -A2 -- '--- SKIP' "$log" >&2
    echo "enterprise hook root worker tests were skipped" >&2
    exit 1
fi
if ! grep -q -- '--- PASS: TestRootGuardian' "$log"; then
    echo "no enterprise hook root worker test ran" >&2
    exit 1
fi
