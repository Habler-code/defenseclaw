# Lifecycle exit codes

Every standalone lifecycle action exits with one of these codes, and so does
every script in `packaging/mdm`. It also prints one lifecycle-result document
(`lifecycle-result.schema.json`) whose `exit_code` field matches the process
exit code.

## Windows (MSI-compatible)

The codes match Windows Installer's codes so Intune and other MDMs classify
them with their default return-code tables.

| Code | Name | Meaning | MDM action |
| --- | --- | --- | --- |
| `0` | success | Installed, upgraded, repaired, removed, or nothing to do (`noop: true`). | Success |
| `1603` | `ERROR_INSTALL_FAILURE` | The action failed. Mutating actions have already rolled back to the previous deployment. | Failure; read `errors[].code` |
| `1618` | `ERROR_INSTALL_ALREADY_RUNNING` | Another lifecycle run holds the lock. | Retry later (Intune's default table retries 1618) |
| `1639` | `ERROR_INVALID_COMMAND_LINE` | Invalid arguments or configuration. Retrying will not help. | Failure; fix the assignment |
| `3010` | `ERROR_SUCCESS_REBOOT_REQUIRED` | Reserved. The standalone lifecycle does not require reboots today. | Soft reboot |

Intune's default Win32 return codes are `0` Success, `1707` Success, `3010`
Soft reboot, `1641` Hard reboot and `1618` Retry. `1603` and `1639` report
as Failed, which is correct. You don't need to add any codes.

## Linux and macOS (sysexits-style)

| Code | Meaning | MDM action |
| --- | --- | --- |
| `0` | Success or nothing to do. | Success |
| `1` | The action failed (already rolled back), or the wrapper refused an input. | Failure; read `errors[].code` |
| `2` | Invalid arguments or configuration. | Failure; fix the script settings |
| `75` | `EX_TEMPFAIL`: another lifecycle run or the package manager holds a lock. | Retry later (set Intune's retry count or your MDM's retry policy) |

## Error codes

`errors[].code` is a stable machine code; `errors[].message` is for humans.
Codes that start with `mdm_` come from the wrapper scripts. They mean the
lifecycle did not run, so `installed: false` in that document means "not
evaluated". Run the `status` action to inspect the host.

| Code | Where | Meaning |
| --- | --- | --- |
| `mdm_invalid_arguments` | all | A flag or setting is missing, malformed or contradictory. |
| `mdm_not_root`, `mdm_not_elevated` | all | Not running as root / SYSTEM / elevated administrator. |
| `mdm_wrong_platform` | unix | The Linux copy ran on macOS or the reverse. |
| `mdm_hash_mismatch` | all | The staged source does not match the pinned SHA-256. |
| `mdm_signature_invalid`, `mdm_signer_not_allowed`, `mdm_signature_unsupported` | all | Signature trust failed, the signer isn't allowed, or signing isn't supported for this source type. |
| `mdm_untrusted_input` | all | A config, credential or keyring file can be changed by a non-administrator. |
| `mdm_untrusted_install` | Windows | The installed CLI or its folders are not administrator-only. |
| `mdm_input_too_large` | all | Config over 1 MiB or credential over 16 KiB. |
| `mdm_payload_invalid`, `mdm_package_invalid`, `mdm_wrong_package`, `mdm_wrong_architecture` | unix | The archive or package is not a DefenseClaw enterprise artifact for this host. |
| `mdm_package_manager_busy` | unix | dpkg, rpm or installer held its lock (exit 75). |
| `mdm_package_install_failed`, `mdm_package_remove_failed`, `mdm_package_manager_missing` | unix | The package manager failed or is absent. |
| `mdm_download_failed`, `mdm_download_unavailable` | unix | The HTTPS download failed, or there is no curl/wget. |
| `mdm_not_installed` | all | A read-only action or source-less `ensure` found no installed deployment. |
| `mdm_lifecycle_no_result`, `mdm_lifecycle_launch_failed` | all | The lifecycle did not start or printed no result. |
| `mdm_secret_failed` | all | The deployment applied but storing the credential failed. |
| `mdm_staging_untrusted`, `mdm_package_incomplete` | all | The private staging folder or the Intune content is not as expected. |
| `unsupported_architecture`, `powershell_constrained_language`, `loader_environment_present`, `powershell7_untrusted` | Windows | Host refusals of the PowerShell 7 wrapper. The lifecycle applies the same checks itself. |

Every other code (for example `config_invalid`, `lifecycle_busy`,
`rolled_back`, `profile_conflict`) comes from the lifecycle itself.
