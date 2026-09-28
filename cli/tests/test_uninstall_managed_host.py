# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""A per-user uninstall on a host with a managed deployment.

On such a host ``defenseclaw-gateway stop`` refuses whenever this account's
own gateway is not running, and a per-user gateway can no longer run there.
The uninstall's gateway-stop phase used to treat that refusal as a failure
and stop before the connector teardown, so a leftover per-user install could
never be removed with its own CLI.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import click
from defenseclaw.commands import cmd_uninstall


def _completed(returncode: int, stderr: str = ""):
    return type("Completed", (), {"returncode": returncode, "stdout": "", "stderr": stderr})()


@unittest.skipIf(sys.platform == "win32", "Linux and macOS managed hosts")
class StopGatewayOnAManagedHostTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name)
        self.gateway = self.data_dir / "defenseclaw-gateway"
        self.gateway.write_bytes(b"#!/bin/sh\n")
        self.plan = cmd_uninstall.UninstallPlan(
            platform_name=sys.platform, gateway_path=str(self.gateway), data_dir=str(self.data_dir)
        )
        self.refusal = _completed(1, "this computer's DefenseClaw is managed by your organization")

    def tearDown(self):
        self._tmp.cleanup()

    def _stop(self, *, managed: str | None):
        with (
            patch("defenseclaw.upgrade_shim.managed_deployment", return_value=managed),
            patch.object(cmd_uninstall.subprocess, "run", side_effect=[_completed(0), self.refusal]) as run,
        ):
            cmd_uninstall._stop_gateway(self.plan)
        self.assertEqual(run.call_args_list[1].args[0], [str(self.gateway), "stop"])

    def test_a_refused_stop_with_no_own_gateway_is_nothing_to_stop(self):
        self._stop(managed="/etc/defenseclaw/runtime.json")

    def test_a_refused_stop_while_this_accounts_gateway_runs_still_fails(self):
        (self.data_dir / "gateway.pid").write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
        with self.assertRaises(click.ClickException) as raised:
            self._stop(managed="/etc/defenseclaw/runtime.json")
        self.assertIn("could not stop sidecar", str(raised.exception))

    def test_a_failed_stop_without_a_managed_deployment_still_fails(self):
        with self.assertRaises(click.ClickException):
            self._stop(managed=None)

    def test_a_stale_pid_file_is_not_a_running_gateway(self):
        # A PID no process has: the refusal is still "nothing to stop".
        (self.data_dir / "gateway.pid").write_text("2147483646\n", encoding="utf-8")
        self._stop(managed="/etc/defenseclaw/runtime.json")


if __name__ == "__main__":
    unittest.main()
