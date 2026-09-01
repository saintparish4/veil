#!/usr/bin/env bash
# Re-records docs/demo.gif.
#
# Needs `asciinema` and `agg` (github.com/asciinema/agg).
#
#   git clone --depth 1 -b v5.0.2 \
#     https://github.com/OpenZeppelin/openzeppelin-contracts /tmp/oz
#   ./docs/record-demo.sh /tmp/oz

set -euo pipefail

COLS=100
ROWS=32
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKOUT="${1:-}"

if [[ -z "$CHECKOUT" || ! -d "$CHECKOUT/contracts" ]]; then
    echo "usage: $0 <openzeppelin-contracts checkout>" >&2
    exit 2
fi

cargo build --release -p veil-cli --manifest-path "$REPO_ROOT/Cargo.toml"

# Staged so the recorded prompt shows `openzeppelin-contracts/contracts` rather
# than whatever absolute path the checkout happens to live at.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp -r "$CHECKOUT" "$STAGE/openzeppelin-contracts"
rm -rf "$STAGE/openzeppelin-contracts/.git"

# `veil` on PATH so the command reads like a real invocation, not a path into
# target/release.
mkdir -p "$STAGE/bin"
ln -sf "$REPO_ROOT/target/release/veil" "$STAGE/bin/veil"

( cd "$STAGE" && PATH="$STAGE/bin:$PATH" TERM=xterm-256color \
    asciinema rec -q --overwrite --cols "$COLS" --rows "$ROWS" \
        -c "$REPO_ROOT/docs/demo.sh" "$REPO_ROOT/docs/demo.cast" )

agg --font-size 15 --theme asciinema "$REPO_ROOT/docs/demo.cast" "$REPO_ROOT/docs/demo.gif"

printf 'wrote docs/demo.gif (%s, %ss)\n' \
    "$(du -h "$REPO_ROOT/docs/demo.gif" | cut -f1)" \
    "$(python3 -c "import json,sys
last=0.0
for line in open('$REPO_ROOT/docs/demo.cast'):
    if line.startswith('['): last=json.loads(line)[0]
print(f'{last:.1f}')")"
