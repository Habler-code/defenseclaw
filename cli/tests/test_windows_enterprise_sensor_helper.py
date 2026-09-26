# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Windows sensor helper service log and Status contracts (#901).

The gateway service depends on the sensor helper, but the helper logged only
to stderr, which the Service Control Manager discards. A helper that failed to
start took the gateway and managed hooks down with nothing on disk.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
HELPER_LOG = ROOT / "cmd" / "defenseclaw-sensor-helper" / "log_windows.go"
HELPER_MAIN = ROOT / "cmd" / "defenseclaw-sensor-helper" / "main.go"
PLANE_WINDOWS = ROOT / "internal" / "sensor" / "plane" / "windows.go"


def _slice(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin : source.index(end, begin + len(start))]


def test_helper_log_is_pinned_in_the_protected_service_environment() -> None:
    module = MODULE.read_text(encoding="utf-8")
    environment = _slice(
        module,
        "function Get-DefenseClawSensorHelperEnvironmentValues",
        "function Set-DefenseClawSensorHelperServiceEnvironment",
    )
    assert '"DEFENSECLAW_WINDOWS_SERVICE_LOG=$LogPath"' in environment
    # Configuration, verification and deployment assertion all render the
    # same environment, so the log path is part of the authenticated contract.
    assert module.count("-LogPath $Layout.SensorHelperLogPath") == 3

    layout = _slice(module, "function Get-DefenseClawLayout", "function Assert-DefenseClawLayoutVolumeIdentity")
    assert "Join-Path $logDirectory 'sensor-helper'" in layout
    assert "Join-Path $sensorHelperLogDirectory 'sensor-helper.log'" in layout

    directories = _slice(module, "function New-DefenseClawLayoutDirectories", "function Assert-DefenseClawManagedHooksActivationRecord")
    assert "$Layout.SensorHelperLogDirectory," in directories
    acls = _slice(module, "function Set-DefenseClawManagedAcls", "function Set-DefenseClawManagedCoreAcls")
    assert "Set-DefenseClawPathAcl -Path $Layout.SensorHelperLogDirectory -Kind AdminDirectory" in acls
    assert "Set-DefenseClawPathAcl -Path $Layout.SensorHelperLogPath -Kind AdminFile" in acls


def test_helper_image_keeps_one_shape_across_versions() -> None:
    # The ImagePath is compared exactly by ownership and configuration checks,
    # and a rollback re-registers the prior helper binary from the current
    # layout. A new command-line flag would break both; the log therefore
    # travels in the service environment, which older helpers ignore.
    module = MODULE.read_text(encoding="utf-8")
    image = _slice(module, "function Get-DefenseClawSensorHelperImage", "function Get-DefenseClawManagedServiceNames")
    assert "return '\"{0}\" --managed-enterprise' -f $Layout.SensorHelperPath" in image
    assert "' --home-dirs" not in image
    assert "--log" not in image
    assert "SensorHelperHomeDirs" not in module
    main = HELPER_MAIN.read_text(encoding="utf-8")
    assert 'flag.String("log"' not in main
    assert "newHelperLogger(serviceLogPath(), os.Stderr)" in main
    assert 'logger.Error("sensor helper exited", "error", err)' in main


def test_windows_plane_takes_no_home_watch_roots() -> None:
    # Why no --home-dirs: the Windows Plane C source is the machine-wide
    # Security event log and ignores the home list entirely.
    plane = PLANE_WINDOWS.read_text(encoding="utf-8")
    assert "func NewSource(_ []string) Source {" in plane


def test_helper_log_open_matches_the_broker_rules() -> None:
    opener = HELPER_LOG.read_text(encoding="utf-8")
    assert 'windowsServiceLogEnv = "DEFENSECLAW_WINDOWS_SERVICE_LOG"' in opener
    assert "managed.ValidateTrustedRuntimeDir(directory" in opener
    assert "winpath.RejectReparseChain(directory)" in opener
    assert "windows.FILE_FLAG_OPEN_REPARSE_POINT" in opener
    assert "windows.FILE_APPEND_DATA" in opener


def test_status_surfaces_the_helper() -> None:
    module = MODULE.read_text(encoding="utf-8")
    status = _slice(module, "function Get-DefenseClawLifecycleStatus", "function Test-DefenseClawGuardianCoverageReport")
    assert "$sensorHelperState = Get-DefenseClawServiceState -Name $Layout.SensorHelperServiceName" in status
    assert "sensor_helper_service = $Layout.SensorHelperServiceName" in status
    assert "sensor_helper_service_state = $sensorHelperState" in status
    assert "sensor_helper_log_path = $Layout.SensorHelperLogPath" in status
    # Reported, not gated: Status ok semantics are unchanged.
    healthy = status[status.index("$healthy = if ($installed) {") : status.index("$externalSecuritySatisfied = [bool](")]
    assert "sensorHelperState" not in healthy
