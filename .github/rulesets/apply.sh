#!/usr/bin/env bash
# Applies the repository's protection as code: the rulesets in this directory. Idempotent; needs
# `gh` authenticated as a repository admin. What they enforce is in README.md next to this script.
#
#   .github/rulesets/apply.sh
set -euo pipefail

repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
here="$(cd "$(dirname "$0")" && pwd)"

for file in "${here}"/*.json; do
  name="$(jq -r .name "${file}")"
  id="$(gh api "repos/${repo}/rulesets" --jq ".[] | select(.name == \"${name}\") | .id")"
  if [ -z "${id}" ]; then
    gh api --method POST "repos/${repo}/rulesets" --input "${file}" --jq '"created ruleset \(.name)"'
  else
    gh api --method PUT "repos/${repo}/rulesets/${id}" --input "${file}" --jq '"updated ruleset \(.name)"'
  fi
done

gh api --method PATCH "repos/${repo}" -F delete_branch_on_merge=true --silent
echo "done"
