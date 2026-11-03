#!/usr/bin/env bash
# Detects when a submodule's build.gradle pins a plugin to a different version
# than settings.gradle.kts (the canonical source).
# Exit non-zero if drift exists. On PRs, comments on the PR with the diff.
# On schedule, opens or updates a 'freshness:plugin-drift' issue.
set -euo pipefail

cd "$(dirname "$0")/.."

# Normalize Kotlin shorthand before comparing both build-file forms.
declare -A canonical
while IFS=':' read -r plugin version; do
    plugin=$(echo "$plugin" | tr -d ' ')
    version=$(echo "$version" | tr -d ' ')
    [ -n "$plugin" ] && canonical["$plugin"]="$version"
done < <(sed -E 's/kotlin\("([^"]+)"\)/id("org.jetbrains.kotlin.\1")/g' settings.gradle.kts \
    | grep -oE 'id\("[^"]+"\)[[:space:]]+version[[:space:]]+"[^"]+"' \
    | sed -E 's/id\("([^"]+)"\)[[:space:]]+version[[:space:]]+"([^"]+)"/\1:\2/')

# Walk every build.gradle in submodules
drift_lines=""
while IFS= read -r build_file; do
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Match Groovy: id 'X' version 'Y' / id "X" version "Y"
        # Match Kotlin: id("X") version "Y"
        if [[ "$line" =~ id[[:space:]]*\([\"\']([^\"\']+)[\"\']\)[[:space:]]+version[[:space:]]+[\"\']([^\"\']+)[\"\'] ]] ||
           [[ "$line" =~ id[[:space:]]*[\"\']([^\"\']+)[\"\'][[:space:]]+version[[:space:]]+[\"\']([^\"\']+)[\"\'] ]]; then
            plugin="${BASH_REMATCH[1]}"
            actual="${BASH_REMATCH[2]}"
            expected="${canonical[$plugin]:-}"
            if [ -n "$expected" ] && [ "$expected" != "$actual" ]; then
                drift_lines+="$build_file: $plugin is at $actual; canonical is $expected"$'\n'
            fi
        fi
    done < <(sed -E 's/kotlin\("([^"]+)"\)/id("org.jetbrains.kotlin.\1")/g' "$build_file")
done < <(find . \( -name build.gradle -o -name build.gradle.kts \) \
        -not -path "./.gradle/*" -not -path "./build/*" \
        -not -path "./node_modules/*" -not -path "./chronicle-web/*" -not -path "./chronicle/*")

if [ -z "$drift_lines" ]; then
    echo "No plugin version drift detected. ✓"
    exit 0
fi

echo "Plugin version drift detected:"
echo "$drift_lines"

repo="${REPO:-uzaira0/chronicle}"
event="${EVENT_NAME:-}"

if [ "$event" = "pull_request" ]; then
    pr="${PR_NUMBER:-}"
    if [ -n "$pr" ]; then
        gh pr comment "$pr" --repo "$repo" --body "Plugin version drift detected:

\`\`\`
$drift_lines
\`\`\`

The canonical source is \`settings.gradle.kts\`. Either bump the submodule build.gradle to match, or bump settings.gradle.kts if the submodule's version is intentional."
    fi
    exit 1
else
    title="freshness:plugin-drift — $(date -u +%Y-%m-%d)"
    body="# Plugin Version Drift

Auto-detected by \`scripts/plugin-drift-detect.sh\`.

\`\`\`
$drift_lines
\`\`\`

Canonical source: \`settings.gradle.kts\`. Bump submodule \`build.gradle\` files to match, or update settings.gradle.kts if the submodule's version is the new target."

    existing=$(gh issue list --repo "$repo" --label "freshness:plugin-drift" --state open \
        --json number --jq '.[0].number // empty')
    if [ -n "$existing" ]; then
        gh issue edit "$existing" --repo "$repo" --title "$title" --body "$body"
    else
        gh label create "freshness:plugin-drift" --repo "$repo" --color "D93F0B" \
            --description "Plugin version drift across submodules" 2>/dev/null || true
        gh issue create --repo "$repo" --title "$title" --body "$body" \
            --label "freshness:plugin-drift"
    fi
    exit 1
fi
