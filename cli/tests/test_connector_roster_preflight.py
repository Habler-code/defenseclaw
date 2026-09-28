# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Unshipped connector handling around upgrades and plugin connectors.

* ``migrate --check`` (the installer's preflight) stops an upgrade that would
  leave only connectors the new gateway cannot load, before anything is
  swapped, and names a command the installed release accepts.
* A plugin manifest that is not UTF-8 declares its directory name only,
  as in the gateway, instead of crashing ``migrate`` and ``setup remove``.
* While ``plugin_dir`` holds a manifest the gateway would load, the gateway
  registers that plugin under the name its code reports, so ``migrate`` does
  not drop a name it cannot rule out.

The connector names are made up on purpose.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
from click.testing import CliRunner
from defenseclaw import migrations
from defenseclaw.commands import cmd_setup
from defenseclaw.commands.cmd_migrate import migrate_cmd
from defenseclaw.commands.cmd_setup import setup as setup_group
from defenseclaw.config import PerConnectorGuardrailConfig
from defenseclaw.connector_paths import declared_plugin_connectors, plugin_dir_may_provide_any_connector

from tests.helpers import cleanup_app, make_app_context

UNSHIPPED = "retired-example"
PLUGIN = "acme"
SHA256 = "a" * 64


def _write(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


class _DataDirCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = os.path.realpath(self._tmp.name)
        self.config_path = os.path.join(self.data_dir, "config.yaml")
        env = {k: v for k, v in os.environ.items() if k not in ("DEFENSECLAW_CONFIG", "DEFENSECLAW_HOME")}
        self._env = patch.dict(os.environ, env, clear=True)
        self._env.start()

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    def config(self, body: str) -> str:
        text = "config_version: 8\n" + body
        _write(self.config_path, text.encode("utf-8"))
        return text

    def plugin(self, directory: str, manifest: bytes) -> None:
        _write(os.path.join(self.data_dir, "plugins", directory, "plugin.yaml"), manifest)

    def read_config(self) -> str:
        with open(self.config_path, encoding="utf-8") as fh:
            return fh.read()


class MigrateCheckStrandedConnectorTests(_DataDirCase):
    def test_check_fails_before_the_swap_when_no_shipped_connector_remains(self):
        body = self.config(
            f"claw:\n  mode: {UNSHIPPED}\nguardrail:\n  connector: {UNSHIPPED}\n  connectors:\n    {UNSHIPPED}: {{}}\n"
        )
        with self.assertRaises(migrations.MigrationError) as raised:
            migrations.migrate(self.data_dir, check=True)
        message = str(raised.exception)
        self.assertIn(repr(UNSHIPPED), message)
        self.assertIn(f"`defenseclaw setup remove {UNSHIPPED} --yes --force`", message)
        self.assertIn("`defenseclaw setup <connector>`", message)
        self.assertIn("nothing was changed", message)
        self.assertNotIn("<name>", message)
        self.assertEqual(self.read_config(), body)

    def test_check_exit_code_stops_the_installer(self):
        self.config(f"guardrail:\n  connector: {UNSHIPPED}\n")
        result = CliRunner().invoke(migrate_cmd, ["--check", "--data-dir", self.data_dir])
        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn(f"defenseclaw setup remove {UNSHIPPED} --yes --force", result.output)

    def test_check_passes_while_a_shipped_connector_remains(self):
        self.config(f"guardrail:\n  connector: {UNSHIPPED}\n  connectors:\n    codex: {{}}\n    {UNSHIPPED}: {{}}\n")
        result = migrations.migrate(self.data_dir, check=True)
        self.assertEqual(result.applied, ["update renamed and removed connectors"])

    def test_migrate_names_the_real_connector_when_it_leaves_the_config_unchanged(self):
        body = self.config(f"guardrail:\n  connector: {UNSHIPPED}\n")
        ctx = migrations.MigrationContext(
            openclaw_home=self.data_dir, data_dir=self.data_dir, config_path=self.config_path
        )
        migrations._migrate_unshipped_connectors(ctx)
        self.assertEqual(self.read_config(), body)
        self.assertEqual(len(ctx.changes), 1)
        self.assertIn("left unchanged", ctx.changes[0])
        self.assertIn(f"`defenseclaw setup remove {UNSHIPPED} --yes`", ctx.changes[0])
        self.assertNotIn("<name>", ctx.changes[0])


class MigrateCheckOlderReleaseHintTests(_DataDirCase):
    def test_check_suggests_setup_remove_only_where_the_installed_release_has_it(self):
        self.config(f"guardrail:\n  connector: {UNSHIPPED}\n")
        for from_version, has_remove in (("0.6.6", False), ("0.5.0", False), ("0.7.0", True), ("0.8.10", True), ("", True)):
            with self.subTest(from_version=from_version):
                with self.assertRaises(migrations.MigrationError) as raised:
                    migrations.migrate(self.data_dir, check=True, from_version=from_version or None)
                message = str(raised.exception)
                self.assertEqual("defenseclaw setup remove" in message, has_remove, msg=message)
                self.assertIn("`defenseclaw setup <connector>`", message)
                if not has_remove:
                    self.assertIn("edit config.yaml", message)


class NonUTF8PluginManifestTests(_DataDirCase):
    LATIN1 = "name: Acm\xe9\n".encode("latin-1")

    def test_manifest_that_is_not_utf8_declares_its_directory_only(self):
        self.plugin(PLUGIN, self.LATIN1)
        plugins = os.path.join(self.data_dir, "plugins")
        self.assertEqual(declared_plugin_connectors(plugins), {PLUGIN})
        self.assertFalse(plugin_dir_may_provide_any_connector(plugins))

    def test_utf16_manifest_with_a_bom_is_read(self):
        self.plugin("bundle", "name: Beta\n".encode("utf-16"))
        self.assertEqual(declared_plugin_connectors(os.path.join(self.data_dir, "plugins")), {"bundle", "beta"})

    def test_migrate_check_and_migrate_do_not_crash(self):
        self.plugin(PLUGIN, self.LATIN1)
        self.config(f"guardrail:\n  connector: codex\n  connectors:\n    codex: {{}}\n    {UNSHIPPED}: {{}}\n")
        result = CliRunner().invoke(migrate_cmd, ["--check", "--data-dir", self.data_dir])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        with patch.object(migrations, "_refresh_local_observability_bundle", lambda *_args: None):
            self.assertTrue(migrations.migrate(self.data_dir).changed)
        self.assertEqual(yaml.safe_load(self.read_config())["guardrail"]["connectors"], {"codex": {}})


class NonUTF8PluginManifestSetupRemoveTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_setup_remove_plugin_connector_with_a_non_utf8_manifest(self):
        self.app.cfg.plugin_dir = os.path.join(self.tmp_dir, "plugins")
        _write(os.path.join(self.app.cfg.plugin_dir, PLUGIN, "plugin.yaml"), NonUTF8PluginManifestTests.LATIN1)
        gc = self.app.cfg.guardrail
        gc.connectors = {"codex": PerConnectorGuardrailConfig(), PLUGIN: PerConnectorGuardrailConfig()}
        gc.connector = "codex"
        self.app.cfg.claw.mode = "codex"
        runtime = cmd_setup._SetupAppliedRuntimeEvidence(
            lifecycle="running", generation="generation-before", invariants=()
        )
        with (
            patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", return_value=True),
            patch("defenseclaw.commands.cmd_setup._capture_setup_applied_runtime", return_value=runtime),
        ):
            result = CliRunner().invoke(
                setup_group, ["remove", PLUGIN, "--yes", "--no-restart"], obj=self.app, catch_exceptions=False
            )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertEqual(set(gc.connectors), {"codex"})
        # The directory still declares the plugin, so it keeps the teardown path.
        self.assertNotIn("not a connector this DefenseClaw build ships", result.output)


@unittest.skipIf(sys.platform == "win32", "the gateway loads Go plugins only on Linux and macOS")
class LoadablePluginNameTests(_DataDirCase):
    MANIFEST = f"name: Acme Connector\nentry: acme.so\nsha256: {SHA256}\n".encode()

    def plugin(self, directory: str, manifest: bytes, *, entry: bool = True) -> None:
        super().plugin(directory, manifest)
        if entry:
            _write(os.path.join(self.data_dir, "plugins", directory, "acme.so"), b"\x7fELF")

    def fake_gateway(self, exit_code: int, stderr: str) -> str:
        """A staged gateway whose ``connector verify`` answers *exit_code*."""
        path = os.path.join(self.data_dir, "staged-gateway")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"#!/bin/sh\necho '{stderr}' >&2\nexit {exit_code}\n")
        os.chmod(path, stat.S_IRWXU)
        return path

    def test_migrate_keeps_a_name_a_loadable_plugin_may_register(self):
        # The gateway registers this plugin as "acme" (the name its code
        # reports), which matches neither its directory nor its manifest.
        self.plugin("acme-connector", self.MANIFEST)
        body = self.config(
            f"claw:\n  mode: {PLUGIN}\nguardrail:\n  connector: {PLUGIN}\n  connectors:\n    {PLUGIN}: {{}}\n    claudecode: {{}}\n"
        )
        ctx = migrations.MigrationContext(
            openclaw_home=self.data_dir, data_dir=self.data_dir, config_path=self.config_path
        )
        migrations._migrate_unshipped_connectors(ctx)
        self.assertEqual(self.read_config(), body)
        self.assertEqual(ctx.changes, [])
        self.assertEqual(migrations._pending_migration_steps(8, None, self.data_dir, self.config_path, 8), [])

    def test_check_passes_for_a_config_whose_only_connector_a_plugin_may_provide(self):
        self.plugin("acme-connector", self.MANIFEST)
        self.config(f"guardrail:\n  connector: {PLUGIN}\n")
        self.assertEqual(migrations.migrate(self.data_dir, check=True).applied, [])

    def test_a_manifest_whose_entry_file_is_missing_does_not_load(self):
        # An unrelated manifest the gateway cannot open must not turn off the
        # preflight stop.
        self.plugin("acme-connector", self.MANIFEST, entry=False)
        self.assertFalse(plugin_dir_may_provide_any_connector(os.path.join(self.data_dir, "plugins")))
        self.config(f"guardrail:\n  connector: {UNSHIPPED}\n")
        result = CliRunner().invoke(migrate_cmd, ["--check", "--data-dir", self.data_dir])
        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn(repr(UNSHIPPED), result.output)

    def test_check_asks_the_staged_gateway_about_a_name_a_plugin_may_provide(self):
        self.plugin("acme-connector", self.MANIFEST)
        self.config(f"guardrail:\n  connector: {UNSHIPPED}\n")
        unknown = self.fake_gateway(2, f'connector verify: unknown connector "{UNSHIPPED}" (known: codex)')
        with self.assertRaises(migrations.MigrationError) as raised:
            migrations.migrate(self.data_dir, check=True, gateway_binary=unknown)
        self.assertIn(repr(UNSHIPPED), str(raised.exception))
        # A gateway that resolves the name (or cannot tell) keeps it.
        for exit_code, stderr in ((0, "clean"), (1, "a plugin may provide it")):
            known = self.fake_gateway(exit_code, stderr)
            self.assertEqual(migrations.migrate(self.data_dir, check=True, gateway_binary=known).applied, [])

    def test_a_manifest_without_entry_and_sha256_does_not_load(self):
        self.plugin("acme-connector", b"name: Acme Connector\n")
        self.assertFalse(plugin_dir_may_provide_any_connector(os.path.join(self.data_dir, "plugins")))
        self.config(f"guardrail:\n  connector: codex\n  connectors:\n    codex: {{}}\n    {PLUGIN}: {{}}\n")
        ctx = migrations.MigrationContext(
            openclaw_home=self.data_dir, data_dir=self.data_dir, config_path=self.config_path
        )
        migrations._migrate_unshipped_connectors(ctx)
        self.assertEqual(yaml.safe_load(self.read_config())["guardrail"]["connectors"], {"codex": {}})


if __name__ == "__main__":
    unittest.main()
