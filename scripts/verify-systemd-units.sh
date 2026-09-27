#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Static check of the standalone systemd units with systemd-analyze verify.
# Every diagnostic fails the check (unknown directives, unknown system calls
# in a filter, bad dependencies), except the one expected on a build host:
# the DefenseClaw binaries named in ExecStart= are not installed there.
#
#   scripts/verify-systemd-units.sh [unit-dir]
set -euo pipefail
dir=${1:-"$(cd "$(dirname "$0")/.." && pwd)/packaging/systemd"}
shopt -s nullglob
units=("$dir"/*.service "$dir"/*.socket "$dir"/*.path "$dir"/*.timer)
if [ ${#units[@]} -eq 0 ]; then
    echo "verify-systemd-units: no units in $dir" >&2
    exit 2
fi
status=0
output=$(systemd-analyze verify --man=no "${units[@]}" 2>&1) || status=$?
unexpected=$(printf '%s\n' "$output" |
    grep -Ev '^[^ ]+: Command /opt/defenseclaw/bin/defenseclaw-(gateway|sensor-helper) is not executable: No such file or directory$' |
    grep -v '^$' || true)
# systemd-analyze exits non-zero for the missing binaries too, so a failure
# counts only when it comes with another diagnostic or with no output.
if [ -n "$unexpected" ] || { [ "$status" -ne 0 ] && [ -z "$output" ]; }; then
    printf '%s\n' "$unexpected" >&2
    echo "verify-systemd-units: systemd-analyze verify reported problems (exit $status)" >&2
    exit 1
fi
echo "verify-systemd-units: ${#units[@]} units verified"
