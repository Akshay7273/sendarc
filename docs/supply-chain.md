# Supply Chain Integrity & Attestations

This document describes SendBeam's software supply chain security architecture, cryptographic build provenance, Software Bill of Materials (SBOM) generation, and CI validation invariants.

---

## 1. Threat Model & Security Invariants

| Attack Vector                                            | Countermeasure                                                                                         | Verification Mechanism                                                                        |
| :------------------------------------------------------- | :----------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------- |
| **Tampered Build Artifacts**                             | Artifacts built exclusively on ephemeral GitHub-hosted runners; strict linear commit history required. | GitHub Build-Provenance Attestations (`actions/attest-build-provenance@v2`).                  |
| **Dependency Confusion / Malicious Transitive Packages** | Frozen dependencies in `go.sum` and `pnpm-lock.yaml`; automated SPDX 2.3 SBOM generation.              | SPDX SBOM manifests (`sendbeam-cli.spdx.json`, `sendbeam-desktop.spdx.json`) attested in CI.  |
| **Forged Checksums**                                     | SHA-256 checksum manifest (`SHA256SUMS.txt`) generated strictly inside the CI manifest workflow.       | Pre-distribution and post-distribution checksum verification gates.                           |
| **Attribution & Committer Spoofing**                     | Strict CI gate rejecting automated agent attribution trailers and enforcing Conventional Commits.      | `metadata & attribution hygiene` status check in `ci.yml`.                                    |
| **Over-Privileged CI Workflows**                         | Default `permissions: contents: read` with least-privilege explicit scopes per job.                    | Explicit job-level permissions (`id-token: write`, `attestations: write`, `packages: write`). |

---

## 2. Cryptographic Build Provenance

SendBeam produces verifiable in-toto build provenance attestations for all compiled binaries, packages, and container images:

1. **Standalone Binaries & Distribution Packages:**
   - Multi-platform CLI archives (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`).
   - Desktop installers and bundles (`.dmg`, `.zip`, `.exe`, `.deb`, `.AppImage`).
   - Attested via `actions/attest-build-provenance@v2` with Sigstore/GitHub OIDC identity tokens.

2. **Container Images:**
   - Multi-arch Docker images (`linux/amd64`, `linux/arm64`) published to GHCR (`ghcr.io/akshay7273/sendbeam`).
   - Built with Buildx `provenance: mode=max` and `sbom: true`.

---

## 3. Software Bill of Materials (SBOM)

Standard SPDX 2.3 JSON SBOM documents are generated automatically during CI packaging via `scripts/generate-sbom.sh`:

- **CLI SBOM:** `sendbeam-cli.spdx.json`
- **Desktop SBOM:** `sendbeam-desktop.spdx.json`

### SPDX 2.3 Structure

Each SBOM document includes:

- `spdxVersion`: `"SPDX-2.3"`
- `dataLicense`: `"CC0-1.0"`
- `SPDXID`: Root document and package identifiers (`SPDXRef-DOCUMENT`, `SPDXRef-Package-sendbeam-cli`)
- Component package information: package name, version, license declaration, repository download location, and supplier identity.
- Relationship graph: `SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-...` and `SPDXRef-Package-... DEPENDS_ON <dependency>`.

### Verification

```bash
# Verify SBOM generation locally:
./scripts/generate-sbom_test.sh
```

---

## 4. Checksum Manifest Invariant

All binary archives, installers, and SBOM documents are hashed with SHA-256 and collected into:

```text
SHA256SUMS.txt
```

Verification command:

```bash
sha256sum -c SHA256SUMS.txt
```
