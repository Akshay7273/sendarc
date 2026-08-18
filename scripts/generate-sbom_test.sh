#!/usr/bin/env bash
# generate-sbom_test.sh — Tests SBOM generation and SPDX 2.3 schema compliance.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "=== Test 1: Generate CLI SBOM to stdout ==="
CLI_SBOM="$("$REPO_ROOT/scripts/generate-sbom.sh" --target cli --version "1.4.0" --commit "abcdef1234567890")"

# Verify SPDX version and properties
echo "$CLI_SBOM" | grep -q '"spdxVersion": "SPDX-2.3"'
echo "$CLI_SBOM" | grep -q '"dataLicense": "CC0-1.0"'
echo "$CLI_SBOM" | grep -q '"SPDXRef-DOCUMENT"'
echo "$CLI_SBOM" | grep -q '"name": "sendbeam-cli"'
echo "$CLI_SBOM" | grep -q '"versionInfo": "1.4.0"'
echo "$CLI_SBOM" | grep -q '"relationshipType": "DESCRIBES"'
echo "$CLI_SBOM" | grep -q '"relationshipType": "DEPENDS_ON"'

# Verify valid JSON parsing via python
python3 -c "import json, sys; data = json.loads(sys.stdin.read()); assert data['spdxVersion'] == 'SPDX-2.3'; assert len(data['packages']) > 1; assert len(data['relationships']) > 1; print(f'Validated CLI SBOM with {len(data[\"packages\"])} packages and {len(data[\"relationships\"])} relationships')" <<< "$CLI_SBOM"

echo "=== Test 2: Generate Desktop SBOM to file ==="
DESKTOP_OUT="$TMP_DIR/desktop-sbom.spdx.json"
"$REPO_ROOT/scripts/generate-sbom.sh" --target desktop --output "$DESKTOP_OUT" --version "1.4.0" --commit "abcdef1234567890"

test -f "$DESKTOP_OUT"
python3 -c "import json; data = json.load(open('$DESKTOP_OUT')); assert data['spdxVersion'] == 'SPDX-2.3'; assert data['packages'][0]['name'] == 'sendbeam-desktop'; assert len(data['packages']) > 1; print(f'Validated Desktop SBOM file with {len(data[\"packages\"])} packages')"

echo "=== ALL SBOM GENERATOR TESTS PASSED ==="
