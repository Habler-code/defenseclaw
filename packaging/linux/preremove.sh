#!/bin/sh
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# defenseclaw-enterprise package: stop and unregister the managed deployment
# before its files are removed. An upgrade is left to the new package's
# postinstall. Never fails the package transaction.

set -u
case "${1:-}" in
    remove | 0) ;;
    *) exit 0 ;; # deb upgrade/deconfigure, rpm upgrade ($1 = 1)
esac

gateway=/opt/defenseclaw/bin/defenseclaw-gateway
state=/var/lib/defenseclaw-enterprise
if [ -x "$gateway" ] && [ -d /run/systemd/system ]; then
    umask 077
    mkdir -p "$state"
    "$gateway" enterprise linux uninstall --json >"$state/last-package-result.json" 2>"$state/last-package-result.log" ||
        echo "defenseclaw-enterprise: uninstall reported a problem; see $state/last-package-result.json" >&2
fi
exit 0
