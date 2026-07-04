#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_HOME="$(mktemp -d "${TMPDIR:-/tmp}/oath-smoke-home.XXXXXX")"
SMOKE_PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/oath-smoke-project.XXXXXX")"
SCOPED_PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/oath-smoke-scoped.XXXXXX")"
ALIAS_PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/oath-smoke-alias.XXXXXX")"
WORKSPACE_PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/oath-smoke-workspace.XXXXXX")"
if [[ -n "${OATH_LAUNCH_TARGET_DIR:-}" ]]; then
  BUILD_TARGET="$OATH_LAUNCH_TARGET_DIR"
  CLEAN_BUILD_TARGET=0
else
  BUILD_TARGET="$(mktemp -d "${TMPDIR:-/tmp}/oath-launch-target.XXXXXX")"
  CLEAN_BUILD_TARGET=1
fi

cleanup() {
  rm -rf "$SMOKE_HOME" "$SMOKE_PROJECT" "$SCOPED_PROJECT" "$ALIAS_PROJECT" "$WORKSPACE_PROJECT"
  if [[ "$CLEAN_BUILD_TARGET" == "1" ]]; then
    rm -rf "$BUILD_TARGET"
  fi
}
trap cleanup EXIT

cd "$ROOT"
export CARGO_TARGET_DIR="$BUILD_TARGET"

echo "using cargo target dir: $CARGO_TARGET_DIR"

echo "==> format"
cargo fmt --all -- --check

echo "==> clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> tests"
cargo test --workspace --locked

if command -v cargo-audit >/dev/null 2>&1; then
  echo "==> cargo audit"
  cargo audit
else
  echo "==> cargo audit skipped: install with 'cargo install cargo-audit'"
fi

echo "==> release build"
cargo build --release --locked --bin oath

echo "==> release smoke install"
(
  cd "$SMOKE_PROJECT"
  BIN="$CARGO_TARGET_DIR/release/oath"
  HOME="$SMOKE_HOME" "$BIN" install --yes is-number
  node -e 'const isNumber = require("is-number"); if (!isNumber(42)) process.exit(1)'

  HOME="$SMOKE_HOME" "$BIN" add --yes is-odd
  node -e 'const isOdd = require("is-odd"); if (!isOdd(3)) process.exit(1)'

  mkdir -p node_modules/stale
  touch node_modules/stale/should-disappear
  HOME="$SMOKE_HOME" "$BIN" ci
  test ! -e node_modules/stale/should-disappear

  HOME="$SMOKE_HOME" "$BIN" remove is-odd
  node -e 'const isNumber = require("is-number"); if (!isNumber(7)) process.exit(1)'
  HOME="$SMOKE_HOME" "$BIN" verify
)

echo "==> release smoke scoped package"
(
  cd "$SCOPED_PROJECT"
  BIN="$CARGO_TARGET_DIR/release/oath"
  HOME="$SMOKE_HOME" "$BIN" add --yes @types/node
  test -e node_modules/@types/node/package.json
)

echo "==> release smoke npm alias"
(
  cd "$ALIAS_PROJECT"
  BIN="$CARGO_TARGET_DIR/release/oath"
  HOME="$SMOKE_HOME" "$BIN" install --yes alias-number@npm:is-number@latest
  node -e 'const isNumber = require("alias-number"); if (!isNumber(9)) process.exit(1)'
)

echo "==> release smoke exec json"
(
  cd "$SMOKE_PROJECT"
  BIN="$CARGO_TARGET_DIR/release/oath"
  HOME="$SMOKE_HOME" "$BIN" exec --dry-run --json is-number > exec.json
  node -e 'const r = require("./exec.json"); if (r.name !== "is-number" || r.decision === "deny") process.exit(1)'
)

echo "==> release smoke global bin"
(
  BIN="$CARGO_TARGET_DIR/release/oath"
  HOME="$SMOKE_HOME" "$BIN" install -g --yes mkdirp
  test -x "$SMOKE_HOME/.oath/global/bin/mkdirp"
)

echo "==> release smoke workspace"
(
  cd "$WORKSPACE_PROJECT"
  mkdir -p packages/a
  printf '%s\n' '{"private":true,"workspaces":["packages/*"]}' > package.json
  printf '%s\n' '{"name":"@smoke/a","version":"1.0.0","dependencies":{"is-number":"^7.0.0"}}' > packages/a/package.json
  BIN="$CARGO_TARGET_DIR/release/oath"
  HOME="$SMOKE_HOME" "$BIN" install --yes
  test -e node_modules/@smoke/a/package.json
)

echo "launch check passed"
