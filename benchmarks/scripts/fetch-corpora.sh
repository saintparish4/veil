#!/usr/bin/env bash
# Veil — clone the precision corpus at pinned revs declared in
# benchmarks/precision/corpus.toml into benchmarks/vendor/precision/.
#
# Re-running is idempotent: if a clone's resolved SHA already matches the
# pinned rev the repo is left alone. Pass `--update` to force re-fetch.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CORPUS_TOML="${ROOT}/benchmarks/precision/corpus.toml"
VENDOR_DIR="${ROOT}/benchmarks/vendor/precision"

UPDATE=0
for arg in "$@"; do
  case "$arg" in
    --update) UPDATE=1 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

if [[ ! -f "$CORPUS_TOML" ]]; then
  echo "fetch-corpora: missing $CORPUS_TOML" >&2
  exit 1
fi

mkdir -p "$VENDOR_DIR"

# Minimal TOML parser — we only read [[corpus]] records. Relying on the
# structure being hand-maintained (see corpus.toml for the schema).
python3 - "$CORPUS_TOML" <<'PY' | while IFS=$'\t' read -r name url rev; do
import sys
try:
    import tomllib  # py 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # pip install tomli on older pythons
data = tomllib.loads(open(sys.argv[1], 'rb').read().decode('utf-8'))
for c in data.get('corpus', []):
    print("\t".join([c['name'], c['url'], c['rev']]))
PY
  target="${VENDOR_DIR}/${name}"
  resolved_file="${target}/.veil-resolved-sha"
  if [[ -f "$resolved_file" ]] && [[ "$UPDATE" -eq 0 ]]; then
    existing="$(cat "$resolved_file" 2>/dev/null || true)"
    echo "fetch-corpora: ${name} — already at ${existing:0:12} (skip; use --update to bump)"
    continue
  fi

  rm -rf "$target"
  mkdir -p "$target"
  (
    cd "$target"
    git init -q
    git remote add origin "$url"
    git fetch --depth 1 origin "$rev" -q || git fetch --depth 1 origin "refs/tags/${rev}" -q
    git checkout --detach FETCH_HEAD -q
    git rev-parse HEAD > .veil-resolved-sha
  )
  echo "fetch-corpora: ${name} — ${rev} → $(cut -c1-12 < "${resolved_file}")"
done

echo "fetch-corpora: done (vendor tree at ${VENDOR_DIR})"
