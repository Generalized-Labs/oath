#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OATH_BIN="${OATH_BIN:-$ROOT/target/release/oath}"
MIN_FREE_MIB="${MIN_FREE_MIB:-1200}"
STAMP="${OATH_COMPAT_STAMP:-$(date -u '+%Y%m%dT%H%M%SZ')}"
RESULTS_DIR="${OATH_COMPAT_RESULTS_DIR:-$ROOT/compat-results/ai-ecosystem/$STAMP}"
LOG_DIR="$RESULTS_DIR/logs"
PROJECT_SNAPSHOT_DIR="$RESULTS_DIR/projects"
RUN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/oath-ai-compat.XXXXXX")"
COMPAT_HOME="$RUN_ROOT/home"

cleanup() {
  rm -rf "$RUN_ROOT"
}
trap cleanup EXIT

mkdir -p "$LOG_DIR" "$PROJECT_SNAPSHOT_DIR" "$COMPAT_HOME"

SUMMARY="$RESULTS_DIR/summary.md"
CASES_JSONL="$RESULTS_DIR/cases.jsonl"
DISK_CSV="$RESULTS_DIR/disk.csv"
METADATA="$RESULTS_DIR/metadata.txt"
PACKAGES="$RESULTS_DIR/packages.txt"

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

free_mib() {
  df -Pm "$ROOT" | awk 'NR == 2 { print $4 }'
}

disk_line() {
  local case_name="$1"
  local phase="$2"
  local available
  available="$(free_mib)"
  printf '%s,%s,%s,%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$case_name" "$phase" "$available" >> "$DISK_CSV"
}

require_space() {
  local case_name="$1"
  local available
  available="$(free_mib)"
  if (( available < MIN_FREE_MIB )); then
    printf 'not enough free space before %s: %s MiB available, need at least %s MiB\n' "$case_name" "$available" "$MIN_FREE_MIB" >&2
    exit 1
  fi
}

write_package_json() {
  local package_name="$1"
  printf '{\n  "name": "%s",\n  "version": "1.0.0",\n  "private": true,\n  "type": "module"\n}\n' "$package_name" > package.json
}

run_case() {
  local case_name="$1"
  local packages="$2"
  local validation="$3"
  local project="$RUN_ROOT/project-$case_name"
  local log="$LOG_DIR/$case_name.log"
  local start_epoch
  local end_epoch
  local duration
  local status="pass"

  require_space "$case_name"
  disk_line "$case_name" "before"
  mkdir -p "$project"
  (
    set -euo pipefail
    cd "$project"
    write_package_json "oath-compat-$case_name"
    printf 'case: %s\n' "$case_name"
    printf 'packages: %s\n' "$packages"
    printf 'project: %s\n' "$project"
    printf 'oath: %s\n' "$OATH_BIN"
    printf 'started: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    if ! HOME="$COMPAT_HOME" "$OATH_BIN" install --yes $packages; then
      exit 1
    fi
    if ! bash -euo pipefail -c "$validation"; then
      exit 1
    fi
    printf 'completed: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  ) > "$log" 2>&1 &
  local pid=$!
  start_epoch="$(date +%s)"
  if ! wait "$pid"; then
    status="fail"
  fi
  end_epoch="$(date +%s)"
  duration=$(( end_epoch - start_epoch ))
  disk_line "$case_name" "after"

  mkdir -p "$PROJECT_SNAPSHOT_DIR/$case_name"
  for artifact in package.json oath-lock.json exec.json; do
    if [[ -e "$project/$artifact" ]]; then
      cp "$project/$artifact" "$PROJECT_SNAPSHOT_DIR/$case_name/$artifact"
    fi
  done

  printf '{"case":"%s","status":"%s","duration_seconds":%s,"packages":"%s","log":"%s"}\n' \
    "$(json_escape "$case_name")" \
    "$status" \
    "$duration" \
    "$(json_escape "$packages")" \
    "$(json_escape "${log#$ROOT/}")" >> "$CASES_JSONL"

  if [[ "$status" != "pass" ]]; then
    printf 'case %s failed; see %s\n' "$case_name" "$log" >&2
    return 1
  fi
}

if [[ ! -x "$OATH_BIN" ]]; then
  printf 'OATH_BIN is not executable: %s\n' "$OATH_BIN" >&2
  printf 'Build first with: cargo build --release --locked --bin oath\n' >&2
  exit 1
fi

metadata_path() {
  local path="$1"
  case "$path" in
    "$ROOT"/*) printf '%s\n' "${path#$ROOT/}" ;;
    *) printf '%s\n' "$(basename "$path")" ;;
  esac
}

printf 'timestamp,case,phase,available_mib\n' > "$DISK_CSV"
: > "$CASES_JSONL"

{
  printf 'started_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'root=<repo-root>\n'
  printf 'oath_bin=%s\n' "$(metadata_path "$OATH_BIN")"
  "$OATH_BIN" --version | sed 's/^/oath_version=/'
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$OATH_BIN" | awk '{ print "oath_sha256=" $1 }'
  fi
  printf 'min_free_mib=%s\n' "$MIN_FREE_MIB"
  printf 'results_dir=%s\n' "$(metadata_path "$RESULTS_DIR")"
  printf 'run_root=<tmp>/%s\n' "$(basename "$RUN_ROOT")"
  printf 'df_before=\n'
  df -h "$ROOT" /private/tmp
} > "$METADATA"

cat > "$PACKAGES" <<'PACKAGES'
core-ai-sdks: openai ai @ai-sdk/openai @ai-sdk/anthropic zod
convex-cli-sdk: convex
agent-protocol: @modelcontextprotocol/sdk @langchain/core
ts-agent-tooling: typescript tsx @types/node
PACKAGES

overall="pass"

if ! run_case \
  "core-ai-sdks" \
  "openai ai @ai-sdk/openai @ai-sdk/anthropic zod" \
  'node --input-type=module -e '\''await import("openai"); await import("ai"); await import("@ai-sdk/openai"); await import("@ai-sdk/anthropic"); const z = await import("zod"); if (!z.z) process.exit(1);'\'''; then
  overall="fail"
fi

if ! run_case \
  "convex-cli-sdk" \
  "convex" \
  'test -e node_modules/convex/package.json; test -x node_modules/.bin/convex; node_modules/.bin/convex --version'; then
  overall="fail"
fi

if ! run_case \
  "agent-protocol" \
  "@modelcontextprotocol/sdk @langchain/core" \
  'node --input-type=module -e '\''await import("@modelcontextprotocol/sdk/client"); await import("@modelcontextprotocol/sdk/server"); await import("@langchain/core/messages");'\'''; then
  overall="fail"
fi

if ! run_case \
  "ts-agent-tooling" \
  "typescript tsx @types/node" \
  'node_modules/.bin/tsc --version; node_modules/.bin/tsx --version; HOME="'"$COMPAT_HOME"'" "'"$OATH_BIN"'" exec --dry-run --json tsx > exec.json; node -e '\''const r = require("./exec.json"); if (r.name !== "tsx" || r.decision === "deny") process.exit(1);'\'''; then
  overall="fail"
fi

{
  printf 'df_after=\n'
  df -h "$ROOT" /private/tmp
  printf 'finished_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'overall=%s\n' "$overall"
} >> "$METADATA"

{
  printf '# AI Ecosystem Compatibility Results\n\n'
  printf '%s\n' "- Started: $(grep '^started_utc=' "$METADATA" | cut -d= -f2-)"
  printf '%s\n' "- Finished: $(grep '^finished_utc=' "$METADATA" | cut -d= -f2-)"
  printf '%s\n' "- Oath: $("$OATH_BIN" --version)"
  if grep -q '^oath_sha256=' "$METADATA"; then
    printf '%s\n' "- Oath SHA-256: \`$(grep '^oath_sha256=' "$METADATA" | cut -d= -f2-)\`"
  fi
  printf '%s\n' "- Overall: $overall"
  printf '%s\n\n' "- Minimum free-space guard: $MIN_FREE_MIB MiB"
  printf '## Cases\n\n'
  while IFS= read -r line; do
    case_name="$(printf '%s' "$line" | sed -n 's/.*"case":"\([^"]*\)".*/\1/p')"
    case_status="$(printf '%s' "$line" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')"
    duration="$(printf '%s' "$line" | sed -n 's/.*"duration_seconds":\([0-9]*\).*/\1/p')"
    package_list="$(printf '%s' "$line" | sed -n 's/.*"packages":"\([^"]*\)".*/\1/p')"
    printf '%s\n' "- \`$case_name\`: $case_status in ${duration}s, packages: \`$package_list\`"
  done < "$CASES_JSONL"
  printf '\n## Disk Samples\n\n'
  printf '```csv\n'
  cat "$DISK_CSV"
  printf '```\n\n'
  printf 'Full logs are saved under `%s`.\n' "${LOG_DIR#$ROOT/}"
} > "$SUMMARY"

ln -sfn "$STAMP" "$ROOT/compat-results/ai-ecosystem/latest"

printf 'AI ecosystem compatibility %s: %s\n' "$overall" "$SUMMARY"

if [[ "$overall" != "pass" ]]; then
  exit 1
fi
