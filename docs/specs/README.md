# Windows managed enterprise specification index

The signed AVC 5.1.22.3763 package embeds DefenseClaw 0.8.6. In this release
branch, only [spec 006](006-windows-cursor-managed-lifecycle/README.md) is
checked in. Code comments still cite specs 003, 004, and 005, whose source
documents are unavailable in this repository. The implementation and its tests
are the reviewable contract for these release features.

| Missing spec | Implemented scope and where to review it |
| --- | --- |
| 003 `windows-deferred-config` | Deferred managed configuration, gateway health state, and guardian readiness: `internal/cli/config_v8_wait.go`, `internal/cli/enterprise_hooks.go`, `internal/gateway/health.go`, `internal/enterprisehooks/guardianstate/`, and their tests. |
| 004 `windows-ui-ipc` | Secure Client GUI AF_UNIX socket path, ACL, and peer-authentication posture: `internal/ipc/`, `internal/config/managed.go`, and their tests. The release's peer-authentication gate is deferred; see `internal/ipc/authposture_gagate.go`. |
| 005 `windows-per-user-hook-lifecycle` | Hook enumerator service, profile discovery, target manifest, and uninstall behavior: `internal/enterprisehooks/enumerator_windows.go`, `internal/cli/enterprise_windows_enumerate_windows.go`, `internal/gateway/health.go`, `packaging/windows/DefenseClawEnterprise.psm1`, and their tests. |

These entries explain the existing references; they do not recreate the absent
requirements or imply that later Secure Client components are in this package.
