#!/usr/bin/env bash
# scripts/version-metadata_test.sh
# Unit tests for authoritative version resolver (scripts/version-metadata.sh)

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${DIR}/version-metadata.sh"

test_case() {
  local ref_type="$1"
  local ref_name="$2"
  local exp_ver="$3"
  local exp_macos_short="$4"
  local exp_macos_bundle="$5"
  local exp_win_fixed="$6"
  local exp_deb="$7"

  local output
  output="$(GITHUB_REF_TYPE="${ref_type}" GITHUB_REF_NAME="${ref_name}" GITHUB_SHA="9908855a5e5f9d410700eedaceb970994cd785ec" "${SCRIPT}" --stdout)"

  local ver macos_short macos_bundle win_fixed deb
  ver="$(echo "${output}" | grep "^version=" | cut -d= -f2)"
  macos_short="$(echo "${output}" | grep "^macos_short_version=" | cut -d= -f2)"
  macos_bundle="$(echo "${output}" | grep "^macos_bundle_version=" | cut -d= -f2)"
  win_fixed="$(echo "${output}" | grep "^windows_fixed_version=" | cut -d= -f2)"
  deb="$(echo "${output}" | grep "^deb_version=" | cut -d= -f2)"

  if [ "${ver}" != "${exp_ver}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected version=${exp_ver}, got ${ver}"
    exit 1
  fi
  if [ "${macos_short}" != "${exp_macos_short}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected macos_short_version=${exp_macos_short}, got ${macos_short}"
    exit 1
  fi
  if [ "${macos_bundle}" != "${exp_macos_bundle}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected macos_bundle_version=${exp_macos_bundle}, got ${macos_bundle}"
    exit 1
  fi
  if [ "${win_fixed}" != "${exp_win_fixed}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected windows_fixed_version=${exp_win_fixed}, got ${win_fixed}"
    exit 1
  fi
  if [ "${deb}" != "${exp_deb}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected deb_version=${exp_deb}, got ${deb}"
    exit 1
  fi

  echo "PASS [${ref_type}:${ref_name}] => ver=${ver}, macos=${macos_short}, win=${win_fixed}, deb=${deb}"
}

echo "=== Running version-metadata test suite ==="

# 1. Exact valid release tags (vX.Y.Z)
test_case "tag" "v1.4.0" "1.4.0" "1.4.0" "1.4.0" "1.4.0.0" "1.4.0"
test_case "tag" "v12.3.45" "12.3.45" "12.3.45" "12.3.45" "12.3.45.0" "12.3.45"

# 2. Invalid or non-conforming tags (must resolve to development)
test_case "tag" "1.4.0" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f"
test_case "tag" "v1.4.0foo" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f"
test_case "tag" "v1.4" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f"
test_case "tag" "v1.4.0-rc1" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f"

# 3. Branches / untagged builds (must resolve to development)
test_case "branch" "main" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f"
test_case "branch" "feat/something" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f"
test_case "" "" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f"

echo "=== All 9 version-metadata test cases passed ==="
