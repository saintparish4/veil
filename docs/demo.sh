#!/usr/bin/env bash
# Drives the terminal recording in README.md.
#
# Scripted rather than typed live so the recording is reproducible: same frames,
# same timings, every run. The command output is real — this types the commands
# and then actually runs them against a checkout of OpenZeppelin.
#
#   ./docs/record-demo.sh        # re-records docs/demo.gif end to end
#
# Expects `veil` on PATH and a project directory as $1.

set -euo pipefail

PROJECT="${1:-openzeppelin-contracts/contracts}"

DIM=$'\033[38;5;245m'
GREEN=$'\033[38;5;77m'
RESET=$'\033[0m'

# Type a command out one character at a time, then run it for real.
run() {
    printf '%s$%s ' "$GREEN" "$RESET"
    local text="$1"
    for (( i = 0; i < ${#text}; i++ )); do
        printf '%s' "${text:i:1}"
        sleep 0.018
    done
    printf '\n'
    sleep 0.45
    eval "$text" || true
}

say() {
    printf '%s%s%s\n' "$DIM" "$1" "$RESET"
    sleep 0.35
}

clear
sleep 1.0

say "# Most Solidity scanners read one file at a time — so when they see"
say "# 'onlyOwner' they have to guess, from the name, whether it protects anything."
say ""
say "# Veil resolves the whole protocol first: imports, inheritance, C3 linearization."
printf '\n'
sleep 0.5

run "veil analyze $PROJECT | head -8"
sleep 5.0

clear
sleep 0.4
say "# 409 imports, none unresolved. So a modifier can be judged by what its"
say "# body actually does, instead of what it happens to be called:"
printf '\n'
sleep 0.5

run "veil analyze $PROJECT --explain-access-control | head -23"
sleep 8.0

clear
sleep 0.4
say "# 'initializer' prevents RE-initialization. It does not restrict WHO calls the"
say "# function — the bug class that froze \$150M in the Parity multisig."
printf '\n'
sleep 0.5

run "veil analyze $PROJECT --compare | head -10"
sleep 6.5

say ""
say "# Per-file analysis reports that function as protected. It is not."
printf '\n'
sleep 4.0
