#!/usr/bin/env bash
# scripts/version-metadata.sh
# Authoritative version-resolution policy for SendBeam CLI and Desktop packaging.
#
# Usage:
#   ./scripts/version-metadata.sh [--github-output] [--env] [--json]
#
# Policy:
#   Untagged / Branch / PR builds:
#     product_version        = dev
#     display_version        = dev
#     numeric_version        = 0.0.0
#     windows_fixed_version  = 0.0.0.0
#     win_major              = 0
#     win_minor              = 0
#     win_patch              = 0
#     win_build              = 0
#     deb_version            = 0.0.0~dev+git.<short_sha>
#
#   Tagged release builds (vX.Y.Z):
#     product_version        = X.Y.Z
#     display_version        = X.Y.Z
#     numeric_version        = X.Y.Z
#     windows_fixed_version  = X.Y.Z.0
#     win_major              = X
#     win_minor              = Y
#     win_patch              = Z
#     win_build              = 0
#     deb_version            = X.Y.Z

set -euo pipefail

REF_TYPE="${GITHUB_REF_TYPE:-}"
REF_NAME="${GITHUB_REF_NAME:-}"
SHA="${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo "0000000000000000000000000000000000000000")}"
SHORT_SHA="${SHA:0:12}"

if [ "${REF_TYPE}" = "tag" ] && [[ "${REF_NAME}" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+ ]]; then
  # Strip leading 'v' if present
  RAW_VER="${REF_NAME#v}"
  PRODUCT_VERSION="${RAW_VER}"
  DISPLAY_VERSION="${RAW_VER}"
  NUMERIC_VERSION="${RAW_VER}"
  DEB_VERSION="${RAW_VER}"

  # Parse semver components for Windows FixedFileInfo
  IFS='.' read -r MAJOR MINOR PATCH <<< "${RAW_VER}"
  WIN_MAJOR="${MAJOR:-0}"
  WIN_MINOR="${MINOR:-0}"
  WIN_PATCH="${PATCH:-0}"
  WIN_BUILD="0"
  WINDOWS_FIXED_VERSION="${WIN_MAJOR}.${WIN_MINOR}.${WIN_PATCH}.${WIN_BUILD}"
else
  PRODUCT_VERSION="dev"
  DISPLAY_VERSION="dev"
  NUMERIC_VERSION="0.0.0"
  DEB_VERSION="0.0.0~dev+git.${SHORT_SHA}"

  WIN_MAJOR="0"
  WIN_MINOR="0"
  WIN_PATCH="0"
  WIN_BUILD="0"
  WINDOWS_FIXED_VERSION="0.0.0.0"
fi

OUTPUT_MODE="${1:---github-output}"

if [ "${OUTPUT_MODE}" = "--github-output" ] && [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "version=${PRODUCT_VERSION}"
    echo "display_version=${DISPLAY_VERSION}"
    echo "numeric_version=${NUMERIC_VERSION}"
    echo "windows_fixed_version=${WINDOWS_FIXED_VERSION}"
    echo "win_major=${WIN_MAJOR}"
    echo "win_minor=${WIN_MINOR}"
    echo "win_patch=${WIN_PATCH}"
    echo "win_build=${WIN_BUILD}"
    echo "deb_version=${DEB_VERSION}"
    echo "commit=${SHA}"
    echo "short_commit=${SHORT_SHA}"
  } >> "${GITHUB_OUTPUT}"
fi

# Also output key=value to stdout for logging / non-Actions usage
cat <<EOF
version=${PRODUCT_VERSION}
display_version=${DISPLAY_VERSION}
numeric_version=${NUMERIC_VERSION}
windows_fixed_version=${WINDOWS_FIXED_VERSION}
win_major=${WIN_MAJOR}
win_minor=${WIN_MINOR}
win_patch=${WIN_PATCH}
win_build=${WIN_BUILD}
deb_version=${DEB_VERSION}
commit=${SHA}
short_commit=${SHORT_SHA}
EOF
