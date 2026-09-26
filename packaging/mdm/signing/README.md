# Signing and trust channels (standalone profile)

Every standalone deployment trusts its payload through exactly one
recorded channel, `enterprise.trust.mode`. The wrappers in `packaging/mdm`
verify the artifact before installing it. The lifecycle re-verifies every
installed file on `verify` and `ensure`.

| Channel | Windows | Linux | macOS | Pin |
| --- | --- | --- | --- | --- |
| **Hash-pinned** (default; works unsigned) | `DefenseClawSetup-Enterprise-Standalone-x64.exe` (flavor `standalone-unsigned`). Setup records the SHA-256 of each inner file from its embedded manifest as the lifecycle's `hash_pinned` anchor. | deb / rpm / payload `.tar.gz` | pkg / payload `.tar.gz` | The artifact's SHA-256, taken from the release's cosign-verified `checksums.txt`, passed to the wrapper as `-Sha256` / `--sha256` |
| **Cisco release signing** (optional release job) | Authenticode on the seven inner files and the outer Setup (flavor `standalone`) | GPG detached `.asc` per package | Developer ID Application (binaries) + Developer ID Installer (pkg) + notarization | Windows: signer certificate SHA-256 (`-AllowedSigners` / `allowedsigners=`); Linux: the public key in a root-owned keyring; macOS: Team ID |
| **Customer re-signing** | Sign the inner files with your certificate, then `packaging/windows/standalone/build-setup.sh --payload-dir <signed>`, or `--sign-command packaging/mdm/signing/authenticode-sign.sh` | Re-sign the packages with your key | Re-sign the pkg with your Developer ID | Your certificate's SHA-256 thumbprint, key or Team ID |
| **AVC-signed standalone** | AVC signs the seven inner files; embed them with `build-setup.sh --payload-dir`. AVC then signs the outer Setup. The Secure Client AVC kit (`packaging/scripts/`) and its output are unchanged. | — | — | Cisco's signer certificate thumbprint |

cosign-signed `checksums.txt` is produced for every release, whichever
channel you use.

## Windows: `authenticode-sign.sh`

```sh
export AUTHENTICODE_PFX=/secure/codesign.pfx AUTHENTICODE_PFX_PASSWORD=...
packaging/windows/standalone/build-setup.sh --version 1.4.0 \
  --sign-command packaging/mdm/signing/authenticode-sign.sh
```

The helper:

- signs PE files and PowerShell scripts in place with osslsigncode 2.5 or
  later, SHA-256, with an RFC 3161 timestamp;
- verifies the result;
- prints `signer_sha256=<thumbprint>`.

The thumbprint is the SHA-256 of the DER signer certificate, the value to
pin. It matches what Windows computes from `SignerCertificate.RawData`, and
that match was verified with a disposable test CA. Set
`AUTHENTICODE_EXPECTED_SHA256` to refuse any other certificate.

The helper never takes secrets on the command line. The PFX password
travels through a 0600 temporary file.

## Why the Secure Client kit is not parameterized here

The Secure Client AVC build kit (`packaging/scripts/*.sh`,
`packaging/scripts/lib/*`) is byte-pinned by the Secure Client source
tripwire (`scripts/secure_client_golden.py`), because it ships production
Secure Client builds. Its fixed `Cisco Systems, Inc.` signer assertion
therefore stays as it is.

Configurable signer pinning lives in the standalone path instead:

- Setup's `allowedsigners=`;
- `defenseclaw.exe enterprise windows ... --allowed-signer`;
- the MDM wrappers' `-AllowedSigners`.
