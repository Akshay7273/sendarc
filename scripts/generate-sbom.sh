#!/usr/bin/env bash
# generate-sbom.sh — Generates SPDX 2.3 standard JSON Software Bill of Materials (SBOM)
# for SendBeam components (CLI and Desktop) from Go module dependencies and build metadata.

set -euo pipefail

TARGET="cli"
OUTPUT=""
VERSION="dev"
COMMIT="unknown"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --output)
      OUTPUT="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --commit)
      COMMIT="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--target cli|desktop] [--output <path>] [--version <ver>] [--commit <sha>]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ "$TARGET" != "cli" && "$TARGET" != "desktop" ]]; then
  echo "Error: --target must be 'cli' or 'desktop'" >&2
  exit 1
fi

COMPONENT_NAME="sendbeam-${TARGET}"
GOMOD_PATH="apps/${TARGET}/go.mod"

if [[ ! -f "$GOMOD_PATH" ]]; then
  echo "Error: $GOMOD_PATH not found" >&2
  exit 1
fi

TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
DOC_UUID="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
DOC_NAMESPACE="https://github.com/Akshay7273/sendbeam/spdxdocs/${COMPONENT_NAME}-${VERSION}-${DOC_UUID}"

# Extract Go dependencies from go.mod
DEPENDENCIES_JSON="[]"
DEPS=()
RELATIONSHIPS=()

# Main document describes root package
RELATIONSHIPS+=("{\"spdxElementId\": \"SPDXRef-DOCUMENT\", \"relatedSpdxElement\": \"SPDXRef-Package-${COMPONENT_NAME}\", \"relationshipType\": \"DESCRIBES\"}")

# Parse direct/indirect require lines in go.mod
while IFS= read -r line; do
  line="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  # Match: module.path vX.Y.Z
  if [[ "$line" =~ ^([a-zA-Z0-9.\/_~-]+)[[:space:]]+(v[0-9a-zA-Z.-]+) ]]; then
    MOD_PATH="${BASH_REMATCH[1]}"
    MOD_VER="${BASH_REMATCH[2]}"
    
    # Sanitize identifier for SPDXID
    SAFE_ID="SPDXRef-Package-$(echo "${MOD_PATH}" | tr '/.~_' '----')"
    
    PKG_ENTRY="{\"SPDXID\": \"${SAFE_ID}\", \"name\": \"${MOD_PATH}\", \"versionInfo\": \"${MOD_VER}\", \"downloadLocation\": \"https://${MOD_PATH}\", \"filesAnalyzed\": false, \"licenseConcluded\": \"NOASSERTION\", \"licenseDeclared\": \"NOASSERTION\", \"supplier\": \"NOASSERTION\"}"
    DEPS+=("$PKG_ENTRY")
    
    RELATIONSHIPS+=("{\"spdxElementId\": \"SPDXRef-Package-${COMPONENT_NAME}\", \"relatedSpdxElement\": \"${SAFE_ID}\", \"relationshipType\": \"DEPENDS_ON\"}")
  fi
done < <(grep -E '^[[:space:]]*[a-zA-Z0-9.\/_~-]+[[:space:]]+v[0-9]' "$GOMOD_PATH" || true)

# Build JSON structure
# Root package
ROOT_PKG="{\"SPDXID\": \"SPDXRef-Package-${COMPONENT_NAME}\", \"name\": \"${COMPONENT_NAME}\", \"versionInfo\": \"${VERSION}\", \"downloadLocation\": \"git+https://github.com/Akshay7273/sendbeam@${COMMIT}\", \"filesAnalyzed\": false, \"homepage\": \"https://omnitrix.space\", \"licenseConcluded\": \"MIT\", \"licenseDeclared\": \"MIT\", \"supplier\": \"Person: Akshay Kumar <https://github.com/Akshay7273>\", \"originator\": \"Person: Akshay Kumar <https://github.com/Akshay7273>\"}"

# Combine packages
ALL_PACKAGES=("$ROOT_PKG")
ALL_PACKAGES+=("${DEPS[@]}")

# Join packages array
PACKAGES_JOINED="$(IFS=,; echo "${ALL_PACKAGES[*]}")"
RELATIONSHIPS_JOINED="$(IFS=,; echo "${RELATIONSHIPS[*]}")"

SPDX_JSON=$(cat <<EOF
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "${COMPONENT_NAME}-${VERSION}-SBOM",
  "documentNamespace": "${DOC_NAMESPACE}",
  "creationInfo": {
    "created": "${TIMESTAMP}",
    "creators": [
      "Tool: SendBeam-SBOM-Generator-1.0",
      "Organization: SendBeam Open Source Project",
      "Person: Akshay Kumar"
    ]
  },
  "packages": [
    ${PACKAGES_JOINED}
  ],
  "relationships": [
    ${RELATIONSHIPS_JOINED}
  ]
}
EOF
)

if [[ -n "$OUTPUT" ]]; then
  mkdir -p "$(dirname "$OUTPUT")"
  echo "$SPDX_JSON" > "$OUTPUT"
  echo "Wrote SPDX 2.3 SBOM to $OUTPUT"
else
  echo "$SPDX_JSON"
fi
