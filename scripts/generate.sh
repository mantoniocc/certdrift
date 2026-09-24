#!/usr/bin/env bash
# Run the certificate scenario generator and publish its output.
#
# Usage:
#   bash scripts/generate.sh           generate into experiments/fixtures/
#   bash scripts/generate.sh --clean   remove generated output and leftovers
#
# Environment:
#   OPENSSL_MODE   docker (default) | local
#   OPENSSL_IMAGE  image used in docker mode, pinned by digest
#
# This script decides where and when the generator runs; what gets generated
# lives in scripts/generate-certs.sh.

set -euo pipefail

OPENSSL_MODE="${OPENSSL_MODE:-docker}"
OPENSSL_IMAGE="${OPENSSL_IMAGE:-alpine/openssl:3.5.8@sha256:6aa2be0ed55a61fff35583e5763c2ea8288bcd3549d316b954b01eec32fb7006}"

# Always run from the repository root: paths below are relative to it.
cd "$(dirname "$0")/.."

GENERATOR="scripts/generate-certs.sh"
OUT="experiments/fixtures"

log() { printf '%s\n' "$*" >&2; }
die() { log "✗ $*"; exit 1; }

# --- Arguments ----------------------------------------------------------------

usage() { log "usage: bash scripts/generate.sh [--clean | --help]"; }

case "${1:-}" in
  "")      ;;
  --clean) rm -rf "${OUT:?}" tmp/fixtures.*; log "✓ removed $OUT and leftovers"; exit 0 ;;
  --help)  usage; exit 0 ;;
  *)       usage; exit 2 ;;
esac

# --- Requirements -------------------------------------------------------------

case "$OPENSSL_MODE" in
  docker)
    command -v docker >/dev/null || die "docker is not installed (or use OPENSSL_MODE=local)"
    docker info >/dev/null 2>&1  || die "docker is installed but the daemon is not running"
    ;;
  local)
    ;;   # the generator checks the local OpenSSL itself
  *)
    die "OPENSSL_MODE must be 'docker' or 'local', got '$OPENSSL_MODE'"
    ;;
esac

# --- Working directory --------------------------------------------------------

rm -rf tmp/fixtures.*                      # leftovers from a killed run
mkdir -p tmp
WORK="$(mktemp -d tmp/fixtures.XXXXXX)"    # relative: same path inside the container
trap 'rm -rf "$WORK"' EXIT

# --- Run the generator --------------------------------------------------------

log "generating in $OPENSSL_MODE mode"

run_generator() {
  if [ "$OPENSSL_MODE" = docker ]; then
    # --init: a tiny PID 1 that forwards Ctrl+C to the generator.
    # The container sees only tmp/ (read-write) and the generator (read-only).
    docker run --rm --init \
      --user "$(id -u):$(id -g)" \
      -v "$PWD/tmp:/work/tmp" \
      -v "$PWD/$GENERATOR:/work/generate-certs.sh:ro" \
      -w /work \
      --entrypoint sh \
      "$OPENSSL_IMAGE" generate-certs.sh "$WORK"
  else
    sh "$GENERATOR" "$WORK"
  fi
}

if ! run_generator; then
  die "generation failed; $OUT was left untouched"
fi

# --- Publish ------------------------------------------------------------------

{
  printf '\nmode: %s\n' "$OPENSSL_MODE"
  if [ "$OPENSSL_MODE" = docker ]; then printf 'image: %s\n' "$OPENSSL_IMAGE"; fi
  printf 'generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >> "$WORK/GENERATED.txt"

# mktemp -d creates the directory as 700; published fixtures must be readable
# by other users too (for example, a container running as another user).
chmod -R u=rwX,go=rX "$WORK"

rm -rf "$OUT"
mv "$WORK" "$OUT"
log "✓ published to $OUT"