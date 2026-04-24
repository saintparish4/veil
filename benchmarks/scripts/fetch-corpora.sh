#!/usr/bin/env bash
# Veil — clone pinned corpora into benchmarks/vendor/<family>/<name>/.
#
# Usage: fetch-corpora.sh [--corpus {all|precision|recall}] [--update]
#
# The TSV (family<TAB>name<TAB>url<TAB>rev) comes from `cargo xtask fetch
# --emit-tsv`, so the canonical corpus schema lives in
# benchmarks/<family>/corpus.toml + xtask/src/cmd/fetch.rs — not in this
# script. Re-running is idempotent: if a clone's resolved SHA already
# matches the pinned rev, the repo is left alone. Pass `--update` to
# force re-fetch.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENDOR_ROOT="${ROOT}/benchmarks/vendor"

CORPUS="all"
UPDATE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --corpus) CORPUS="$2"; shift 2 ;;
    --update) UPDATE=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

case "$CORPUS" in
  all|precision|recall) ;;
  *) echo "unknown --corpus: $CORPUS (supported: all, precision, recall)" >&2; exit 2 ;;
esac

mkdir -p "$VENDOR_ROOT"

# Process-substitution keeps the while-loop in the parent shell so
# exit status from the xtask call is observable via `pipefail`.
while IFS=$'\t' read -r family name url rev; do
  [[ -z "${family:-}" ]] && continue
  family_dir="${VENDOR_ROOT}/${family}"
  target="${family_dir}/${name}"
  resolved_file="${target}/.veil-resolved-sha"
  mkdir -p "$family_dir"

  if [[ -f "$resolved_file" ]] && [[ "$UPDATE" -eq 0 ]]; then
    existing="$(cat "$resolved_file" 2>/dev/null || true)"
    echo "fetch-corpora: ${family}/${name} — already at ${existing:0:12} (skip; use --update to bump)"
    continue
  fi

  rm -rf "$target"
  mkdir -p "$target"
  (
    cd "$target"
    git init -q
    git remote add origin "$url"
    git fetch --depth 1 origin "$rev" -q \
      || git fetch --depth 1 origin "refs/tags/${rev}" -q
    git checkout --detach FETCH_HEAD -q
    git rev-parse HEAD > .veil-resolved-sha
  )
  echo "fetch-corpora: ${family}/${name} — ${rev} → $(cut -c1-12 < "${resolved_file}")"
done < <(cargo run --quiet -p xtask -- fetch --corpus "$CORPUS" --emit-tsv)

echo "fetch-corpora: done (vendor tree at ${VENDOR_ROOT})"
