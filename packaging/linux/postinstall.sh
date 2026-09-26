#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise package: apply the standalone managed deployment
# after an install or upgrade (deb configure, rpm %post).
#
# This script never fails the package transaction. The lifecycle validates
# the administrator config, activates the services and rolls back on its
# own; its JSON result is kept in the lifecycle directory and
# `defenseclaw-gateway enterprise linux verify` reports any problem.

set -u
gateway=/opt/defenseclaw/bin/defenseclaw-gateway
state=/var/lib/defenseclaw-enterprise

if [ ! -d /run/systemd/system ]; then
    echo "defenseclaw-enterprise: systemd is not running; run '$gateway enterprise linux ensure --from-package' on a systemd host." >&2
    exit 0
fi

systemd-sysusers /usr/lib/sysusers.d/defenseclaw.conf >/dev/null 2>&1 || true
systemd-tmpfiles --create /usr/lib/tmpfiles.d/defenseclaw.conf >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true

umask 077
mkdir -p "$state" && chmod 0700 "$state"
if "$gateway" enterprise linux ensure --from-package --reason package --json \
    >"$state/last-package-result.json" 2>"$state/last-package-result.log"; then
    echo "defenseclaw-enterprise: the managed deployment is active."
else
    echo "defenseclaw-enterprise: installed, but the lifecycle reported a problem." >&2
    echo "  See $state/last-package-result.json or run: sudo $gateway enterprise linux verify" >&2
fi
exit 0
