# Intune on Linux: platform script

Intune manages **Ubuntu Desktop** and **Red Hat Enterprise Linux 8 and 9**
devices enrolled with the Microsoft Intune app. It deploys **Bash platform
scripts** (`.sh` files) but no Linux app packages. So a root platform script
downloads, verifies, installs and configures DefenseClaw.

## Script

1. Host `defenseclaw-enterprise-<version>-linux-<arch>.deb` (Ubuntu) or
   `.rpm` (RHEL) on HTTPS. Instead, you can host the architecture's
   `.tar.gz` payload, which works on both.
2. Edit `packaging/mdm/linux/defenseclaw-enterprise.sh`. In the settings
   block, set:
   - `DC_SOURCE_URL` and `DC_SOURCE_SHA256` (from the cosign-verified
     `checksums.txt`);
   - for GPG trust, also `DC_TRUST_MODE=signed`, `DC_GPG_KEYRING` (a
     root-owned keyring you deploy separately) and `DC_SIGNATURE_URL` (the
     release's `.asc`).

   Paste the administrator config between the `DEFENSECLAW_CONFIG` markers.

   Ubuntu and RHEL need different package files. Create one script per
   distribution and target each at a device group filtered by OS, or use
   the payload archive for both.
3. In the Intune admin center, go to **Devices > Manage devices > Scripts and
   remediations > Platform scripts > Add > Linux**:

   | Setting | Value |
   | --- | --- |
   | Execution context | **Root**. The first run can prompt the user for consent. |
   | Execution frequency | Every 15 minutes (the default) up to daily. `ensure` does nothing when the host already matches. |
   | Execution retries | 3. Exit `75` means dpkg, rpm or the lifecycle was busy. |
   | Execution script | the edited `defenseclaw-enterprise.sh` |

## Inventory and removal

- Inventory: run `packaging/mdm/linux/detect.sh --format value` as a second
  platform script. It prints the installed version, `not-installed`,
  `outdated` or `unhealthy`, and always exits 0.
- Removal: assign `packaging/mdm/linux/uninstall.sh` as a root platform
  script. It removes the deployment and the deb/rpm; use `DC_PURGE=1` to
  also remove config, credentials and state.

## The Cisco AI Defense key

Microsoft states that custom scripts and settings must not carry sensitive
information, so do not embed the key in the script. Deliver it once through
an administrator channel, such as SSH, configuration management or a
secrets agent:

```sh
sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise secret set --name ai-defense-api-key --from-stdin </secure/key
```

## Notes

- Hosts must run systemd 239 or later. On a host without systemd the
  package installs but reports that the deployment is inactive.
- SELinux enforcing (RHEL) is supported. The lifecycle relabels the files it
  installs.
- The wrapper writes `/var/log/defenseclaw-enterprise-mdm.log` (root,
  0600).
