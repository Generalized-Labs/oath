#!/bin/sh
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/oath-readme-smoke.XXXXXX")
BIN_DIR="$WORK_DIR/bin"
PROJECT_DIR="$WORK_DIR/project"
HOME_DIR="$WORK_DIR/home"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$BIN_DIR" "$PROJECT_DIR" "$HOME_DIR"

# Keep the package store, cache, approvals, and transparency data isolated from
# the developer account running this check.
HOME="$HOME_DIR"
USERPROFILE="$HOME_DIR"
export HOME USERPROFILE

OATH_INSTALL="$BIN_DIR" sh "$REPO_ROOT/install.sh"
PATH="$BIN_DIR:$PATH"
export PATH

oath --version

cd "$PROJECT_DIR"
oath init oath-readme-smoke
oath add picocolors@1.1.1
oath verify

ASSESSMENT=$(oath exec --dry-run --json prettier@3.7.4)
printf '%s\n' "$ASSESSMENT" | grep -F '"name": "prettier"' >/dev/null
printf '%s\n' "$ASSESSMENT" | grep -F '"version": "3.7.4"' >/dev/null
printf '%s\n' "$ASSESSMENT" | grep -F '"integrity":' >/dev/null
printf '%s\n' "$ASSESSMENT" | grep -F '"decision":' >/dev/null

printf '%s\n' "README release smoke passed"
