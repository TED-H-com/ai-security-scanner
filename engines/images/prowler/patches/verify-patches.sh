#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly PIN="499fd637f3393b485833b08cdaf4172917c5698e"
readonly PATCH_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PYTHON="${PYTHON:-python3}"
readonly EXPECTED_SERIES=$'0001-azure-static-access-token-iam-only.patch\n0002-gcp-exact-project-lookups.patch\n0003-gcp-disable-ambient-organization-search.patch\n0004-gcp-disable-provider-organization-lookup.patch\n0005-azure-disable-tenant-enumeration.patch\n0006-azure-require-enabled-subscription.patch'

usage() {
  echo "usage: $0 /path/to/prowler [--pytest]" >&2
  exit 2
}

[[ $# -eq 1 || $# -eq 2 ]] || usage
[[ $# -eq 1 || "$2" == "--pytest" ]] || usage

actual_series="$(cat -- "${PATCH_DIR}/series")"
if [[ "$actual_series" != "$EXPECTED_SERIES" ]]; then
  echo "Prowler patch series differs from the reviewed order" >&2
  diff <(printf '%s\n' "$EXPECTED_SERIES") <(printf '%s\n' "$actual_series") >&2 || true
  exit 1
fi

expected_patch_digest() {
  case "$1" in
    0001-azure-static-access-token-iam-only.patch)
      printf '%s\n' '053ef441588b6bff99aef8a568f2617d8933a46449d2f9c2804b796c7a39566a'
      ;;
    0002-gcp-exact-project-lookups.patch)
      printf '%s\n' '7a22e58b3c700813e3b7e814dd04254dd90ddbdbdfbccd917c3b477e487c2fcb'
      ;;
    0003-gcp-disable-ambient-organization-search.patch)
      printf '%s\n' '136335c3b7defd5a167aa6d07633bcb8f5c99c6f98b398eff01fc15d11a417d1'
      ;;
    0004-gcp-disable-provider-organization-lookup.patch)
      printf '%s\n' 'ffef7b02808bbb85f1f7d28ab3c453237b33cde45729daa51feb37633e1fd79a'
      ;;
    0005-azure-disable-tenant-enumeration.patch)
      printf '%s\n' '00f40971d80137612b5327a8b7e31de6b05b08dd8239f1bd635339ae6325f80b'
      ;;
    0006-azure-require-enabled-subscription.patch)
      printf '%s\n' '47b4202cdfe545b699fbe0b0dfc3e5d249d94e9d00cf7d61388405071e5aaeba'
      ;;
    *) return 1 ;;
  esac
}

expected_patch_files() {
  case "$1" in
    0001-azure-static-access-token-iam-only.patch)
      printf '%s\n' \
        'prowler/providers/azure/azure_provider.py' \
        'prowler/providers/azure/lib/arguments/arguments.py' \
        'prowler/providers/common/provider.py' \
        'tests/providers/azure/azure_access_token_auth_test.py'
      ;;
    0002-gcp-exact-project-lookups.patch)
      printf '%s\n' \
        'prowler/providers/gcp/gcp_provider.py' \
        'tests/providers/gcp/gcp_exact_projects_test.py'
      ;;
    0003-gcp-disable-ambient-organization-search.patch)
      printf '%s\n' \
        'prowler/providers/gcp/services/cloudresourcemanager/cloudresourcemanager_service.py' \
        'tests/providers/gcp/services/cloudresourcemanager/cloudresourcemanager_service_test.py'
      ;;
    0004-gcp-disable-provider-organization-lookup.patch)
      printf '%s\n' \
        'prowler/providers/gcp/gcp_provider.py' \
        'tests/providers/gcp/gcp_exact_projects_test.py'
      ;;
    0005-azure-disable-tenant-enumeration.patch)
      printf '%s\n' \
        'prowler/lib/outputs/finding.py' \
        'prowler/providers/azure/azure_provider.py' \
        'tests/providers/azure/azure_access_token_auth_test.py'
      ;;
    0006-azure-require-enabled-subscription.patch)
      printf '%s\n' \
        'prowler/providers/azure/azure_provider.py' \
        'tests/providers/azure/azure_access_token_auth_test.py'
      ;;
    *) return 1 ;;
  esac
}

readonly SOURCE_REPO="$(realpath -- "$1")"
git -C "$SOURCE_REPO" rev-parse --git-dir >/dev/null
git -C "$SOURCE_REPO" cat-file -e "${PIN}^{commit}"

temp_parent="$(mktemp -d "${TMPDIR:-/var/tmp}/ai-security-scanner-prowler-patches.XXXXXX")"
temp_tree="${temp_parent}/tree"

cleanup() {
  if [[ -e "$temp_tree" ]]; then
    git -C "$SOURCE_REPO" worktree remove --force "$temp_tree" >/dev/null 2>&1 || true
  fi
  if [[ -d "$temp_parent" ]]; then
    rmdir "$temp_parent" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

git -C "$SOURCE_REPO" worktree add --quiet --detach "$temp_tree" "$PIN"
[[ "$(git -C "$temp_tree" rev-parse HEAD)" == "$PIN" ]]

while IFS= read -r patch_name; do
  [[ -n "$patch_name" ]] || continue
  [[ "$patch_name" =~ ^[0-9]{4}-[a-z0-9-]+\.patch$ ]] || {
    echo "invalid patch name in series: $patch_name" >&2
    exit 1
  }
  patch_path="${PATCH_DIR}/${patch_name}"
  [[ -f "$patch_path" ]] || {
    echo "missing patch: $patch_path" >&2
    exit 1
  }
  expected_digest="$(expected_patch_digest "$patch_name")"
  actual_digest="$(sha256sum -- "$patch_path" | awk '{print $1}')"
  [[ "$actual_digest" == "$expected_digest" ]] || {
    echo "patch digest differs: $patch_name" >&2
    exit 1
  }
  expected_diff_files="$(expected_patch_files "$patch_name")"
  actual_diff_files="$(git apply --numstat "$patch_path" | cut -f3- | sort)"
  if [[ "$actual_diff_files" != "$expected_diff_files" ]]; then
    echo "patch file set differs: $patch_name" >&2
    diff \
      <(printf '%s\n' "$expected_diff_files") \
      <(printf '%s\n' "$actual_diff_files") >&2 || true
    exit 1
  fi
  git -C "$temp_tree" apply --check "$patch_path"
  git -C "$temp_tree" apply "$patch_path"
done <"${PATCH_DIR}/series"

readonly EXPECTED_FILES=$'prowler/lib/outputs/finding.py\nprowler/providers/azure/azure_provider.py\nprowler/providers/azure/lib/arguments/arguments.py\nprowler/providers/common/provider.py\nprowler/providers/gcp/gcp_provider.py\nprowler/providers/gcp/services/cloudresourcemanager/cloudresourcemanager_service.py\ntests/providers/azure/azure_access_token_auth_test.py\ntests/providers/gcp/gcp_exact_projects_test.py\ntests/providers/gcp/services/cloudresourcemanager/cloudresourcemanager_service_test.py'
actual_files="$(git -C "$temp_tree" status --short | sed 's/^...//' | sort)"
if [[ "$actual_files" != "$EXPECTED_FILES" ]]; then
  echo "patched file set differs from the reviewed allowlist" >&2
  diff <(printf '%s\n' "$EXPECTED_FILES") <(printf '%s\n' "$actual_files") >&2 || true
  exit 1
fi

git -C "$temp_tree" diff --check
"$PYTHON" -m compileall -q \
  "$temp_tree/prowler/lib/outputs/finding.py" \
  "$temp_tree/prowler/providers/azure/azure_provider.py" \
  "$temp_tree/prowler/providers/azure/lib/arguments/arguments.py" \
  "$temp_tree/prowler/providers/common/provider.py" \
  "$temp_tree/prowler/providers/gcp/gcp_provider.py" \
  "$temp_tree/prowler/providers/gcp/services/cloudresourcemanager/cloudresourcemanager_service.py" \
  "$temp_tree/tests/providers/azure/azure_access_token_auth_test.py" \
  "$temp_tree/tests/providers/gcp/gcp_exact_projects_test.py" \
  "$temp_tree/tests/providers/gcp/services/cloudresourcemanager/cloudresourcemanager_service_test.py"

if [[ $# -eq 2 ]]; then
  (
    cd "$temp_tree"
    "$PYTHON" -m pytest -q \
      tests/lib/outputs/finding_test.py \
      tests/lib/outputs/ocsf/ocsf_test.py \
      tests/providers/azure/azure_access_token_auth_test.py \
      tests/providers/azure/azure_provider_test.py \
      tests/providers/gcp/gcp_exact_projects_test.py \
      tests/providers/gcp/gcp_provider_test.py \
      tests/providers/gcp/services/cloudresourcemanager/cloudresourcemanager_service_test.py \
      tests/providers/gcp/services/iam/iam_audit_logs_enabled/iam_audit_logs_enabled_test.py \
      tests/providers/gcp/services/iam/iam_no_service_roles_at_project_level/iam_no_service_roles_at_project_level_test.py \
      tests/providers/gcp/services/iam/iam_role_kms_enforce_separation_of_duties/iam_role_kms_enforce_separation_of_duties_test.py \
      tests/providers/gcp/services/iam/iam_role_sa_enforce_separation_of_duties/iam_role_sa_enforce_separation_of_duties_test.py \
      tests/lib/cli/parser_test.py \
      -p no:randomly
  )
fi

echo "Prowler patches verified at ${PIN}"
