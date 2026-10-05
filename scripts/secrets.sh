#!/usr/bin/env bash
# Secret scan: runs gitleaks over the whole git history of HEAD (every commit
# reachable from it, so a pull request's own commits and the commits pushed
# to main are always included) with the repo's .gitleaks.toml and
# .gitleaksignore. Fails if any finding is not allowlisted. Secrets are
# redacted in the output, which is public in CI logs.
#
# gitleaks is a pinned release binary whose archive is checked against the
# SHA-256 below on every run (cached in ~/.cache/verilog-ci). The CI
# `secrets` job and `make ci` both run this script, so they use the same
# version.
#
# Usage: scripts/secrets.sh
# Requires: git (full, non-shallow history), curl, tar.
set -euo pipefail

GITLEAKS_VERSION=8.30.1
# From gitleaks_8.30.1_checksums.txt of the GitHub release.
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) PLATFORM=linux_x64 SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
  Linux-aarch64 | Linux-arm64) PLATFORM=linux_arm64 SHA256=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;;
  Darwin-arm64) PLATFORM=darwin_arm64 SHA256=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 ;;
  Darwin-x86_64) PLATFORM=darwin_x64 SHA256=dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709 ;;
  *) echo "secrets: no pinned gitleaks build for $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ "$(git rev-parse --is-shallow-repository)" = true ]; then
  echo "secrets: shallow clone; the scan needs the full history (actions/checkout fetch-depth: 0)" >&2
  exit 2
fi

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'; }

ARCHIVE="gitleaks_${GITLEAKS_VERSION}_${PLATFORM}.tar.gz"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/verilog-ci"
mkdir -p "$CACHE"
if [ ! -f "$CACHE/$ARCHIVE" ] || [ "$(sha256 "$CACHE/$ARCHIVE")" != "$SHA256" ]; then
  echo "secrets: downloading gitleaks $GITLEAKS_VERSION ($PLATFORM)"
  curl -fsSL -o "$CACHE/$ARCHIVE.part" \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${ARCHIVE}"
  mv "$CACHE/$ARCHIVE.part" "$CACHE/$ARCHIVE"
fi
have="$(sha256 "$CACHE/$ARCHIVE")"
if [ "$have" != "$SHA256" ]; then
  rm -f "$CACHE/$ARCHIVE"
  echo "secrets: checksum mismatch for $ARCHIVE: got $have, want $SHA256" >&2
  exit 1
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/verilog-secrets.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
tar -xzf "$CACHE/$ARCHIVE" -C "$TMP" gitleaks

echo "secrets: gitleaks $("$TMP/gitleaks" version) over the history of $(git rev-parse HEAD)"
"$TMP/gitleaks" git \
  --config .gitleaks.toml \
  --gitleaks-ignore-path .gitleaksignore \
  --log-opts="--full-history HEAD" \
  --redact --verbose --no-banner --no-color \
  .
