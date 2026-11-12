#!/usr/bin/env bash
# End to end inside the image (read-only root, no capabilities, no network): a corpus of generated PE files with damaged
# copies is written, scanned against its truth with YARA and pefile, scanned again from a read-only mount, a report is
# rebuilt exactly from its JSON, the two ways of computing are verified and the benchmark runs small. Needs Docker.
# Usage: tools/docker_e2e.sh [image]
set -euo pipefail
IMAGE="${1:-pescan}"
VOL="pescan-e2e-$$"
TMP="$(mktemp -d)"
trap 'docker volume rm -f "$VOL" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

[ "$(docker run --rm --entrypoint id "$IMAGE" -u)" != 0 ]   # not root
docker volume create "$VOL" >/dev/null
docker run --rm --user 0 -v "$VOL":/data --entrypoint chown "$IMAGE" 10001 /data

SECURE=(--read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --network none)
RUN=(docker run --rm "${SECURE[@]}" -v "$VOL":/data "$IMAGE")
cat_file() { docker run --rm --entrypoint cat -v "$VOL":/data "$IMAGE" "$1" > "$2"; }

"${RUN[@]}" corpus /data/c --files 60 --seed 3 --damaged 1 | grep -q '60 files, 60 damaged copies'
out="$("${RUN[@]}" scan /data/c --reference --workers 2 --out /data/r 2>/dev/null)"
grep -q '121 files, 104 PE' <<<"$out"
grep -q 'against the truth: 60 of 60 files exactly right (Python), 60 (YARA)' <<<"$out"
grep -q 'pefile: 102 of 103 files read identically, 1 refused by pefile' <<<"$out"
cat_file /data/r/report.json "$TMP/report.json"
grep -q '"kind": "scan"' "$TMP/report.json"
cat_file /data/r/report.md "$TMP/report.md"
"${RUN[@]}" render /data/r/report.json -o /data/r/again.md >/dev/null
cat_file /data/r/again.md "$TMP/again.md"
cmp "$TMP/again.md" "$TMP/report.md"                              # the report is rebuilt exactly from the JSON
cat_file /data/r/summary.png "$TMP/summary.png"
[ "$(head -c 4 "$TMP/summary.png" | tail -c 3)" = "PNG" ]

# the files to analyse mounted read-only, the way a real folder is scanned
out="$(docker run --rm "${SECURE[@]}" -v "$VOL":/in:ro "$IMAGE" scan /in/c --depth 0 --name "read-only" 2>/dev/null)"
grep -q 'read-only: 61 files, 60 PE' <<<"$out"

"${RUN[@]}" show /data/c/sample00001.exe | grep -q '"kind": "pe"'
"${RUN[@]}" rules | grep -q '^rule overlay : indicator'

out="$("${RUN[@]}" verify --files 40)"
grep -q '^6 of 6 checks passed' <<<"$out"

"${RUN[@]}" bench --sizes 20 --workers 1,2 --repeat 1 --verify-files 20 --out /data/bench >/dev/null
cat_file /data/bench/bench.json "$TMP/bench.json"
grep -q '"ok": true' "$TMP/bench.json"

set +e; "${RUN[@]}" scan /data/nope >/dev/null 2>&1; rc=$?; set -e   # a missing path is exit code 2
[ "$rc" = 2 ]
echo "docker end-to-end: OK"
