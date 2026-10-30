#!/usr/bin/env bash
# Run the container-safe roles in a pinned Arch Linux image, against the PAM
# state Omarchy leaves behind, and check the result with tools independent of
# the roles themselves.
#
# Usage: tests/container/run.sh [SHARD]   (needs podman)
#   No SHARD runs every section. SHARD 1-3 runs the common setup (everything
#   in inside.sh before the first shard's section) and then one shard's
#   sections, as CI does in parallel.
set -euo pipefail

# archlinux:base, multi-arch index digest, published 2026-10-19.
readonly IMAGE='docker.io/library/archlinux@sha256:e43f1fd80e073992c5f173efbbbf65144170bf60aeb7369940087d63eacea8f4'
# Where each shard starts: the start of a section title in inside.sh. A shard
# runs to the next shard's start; the last one to the final count. Balanced
# from the section times of a CI run (2026-10-28, 1683 s in the container).
readonly SHARD_STARTS=('--- su: real logins' '--- package drift: a modified binary' '--- D-27/D-28')

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
shard=${1:-}

command -v podman >/dev/null 2>&1 || { echo "error: podman is required" >&2; exit 2; }
[[ -z $shard || $shard =~ ^[1-9]$ && $shard -le ${#SHARD_STARTS[@]} ]] ||
  { echo "error: SHARD must be 1-${#SHARD_STARTS[@]}" >&2; exit 2; }

out_dir="$repo_root/tests/container/.out"
rm -rf "$out_dir" && mkdir -p "$out_dir"

# Cut inside.sh into setup + shards, on every run, so a renamed section fails
# here and not as a shard that silently runs nothing. The shards must cover
# every check exactly once: their counts, less the setup's repeated in each,
# add up to checks_total.
inside="$repo_root/tests/container/inside.sh"
starts=()
for title in "${SHARD_STARTS[@]}"; do
  # || true: a title that matches nothing must reach the error below, not end
  # the script at this assignment (set -e, pipefail).
  lines=$(grep -nF -e "echo \"$title" "$inside" | cut -d: -f1 || true)
  [[ $(wc -l <<<"$lines") -eq 1 && -n $lines ]] || { echo "error: shard start '$title' found ${lines:-0 times}" >&2; exit 2; }
  ((${#starts[@]} == 0 || lines > starts[${#starts[@]} - 1])) || { echo "error: shard start '$title' is out of order" >&2; exit 2; }
  starts+=("$lines")
done
# shellcheck disable=SC2016 # the pattern is inside.sh's literal text
end=$(grep -n '^\[\[ \$checks_passed -eq \$checks_total \]\]' "$inside" | cut -d: -f1 || true)
[[ -n $end && $end -gt ${starts[${#starts[@]} - 1]} ]] || { echo "error: final count line not found after the last shard" >&2; exit 2; }
checks() { sed -n "$1,$2p" "$inside" | grep -c '^pass ' || true; }
setup_checks=$(checks 1 $((starts[0] - 1)))
total=$(sed -n 's/^checks_total=\([0-9]*\)$/\1/p' "$inside")
sum=$setup_checks
for i in "${!starts[@]}"; do
  last=$((i + 1 < ${#starts[@]} ? starts[i + 1] - 1 : end - 1))
  sum=$((sum + $(checks "${starts[i]}" "$last")))
done
[[ $sum -eq $total ]] || { echo "error: shards hold $sum checks, checks_total is $total" >&2; exit 2; }

script=/src/tests/container/inside.sh
if [[ -n $shard ]]; then
  i=$((shard - 1))
  last=$((i + 1 < ${#starts[@]} ? starts[i + 1] - 1 : end - 1))
  n=$((setup_checks + $(checks "${starts[i]}" "$last")))
  { sed -n "1,$((starts[0] - 1))p" "$inside" | sed "s/^checks_total=[0-9]*\$/checks_total=$n/"
    sed -n "${starts[i]},${last}p;${end},\$p" "$inside"; } >"$out_dir/inside-shard.sh"
  script=/out/inside-shard.sh
  echo "shard $shard: lines ${starts[i]}-$last of inside.sh after the setup, $n of $total checks"
fi

# NET_ADMIN/NET_RAW let ufw program netfilter inside the container.
# Run detached and wait in a retry loop: on macOS the client's API connection
# to the podman machine was seen to drop mid-run ("wait for container: EOF"),
# which killed an attached run although the container was fine.
cid=$(podman run -d --platform linux/amd64 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$repo_root:/src:ro" -v "$out_dir:/out" \
  "$IMAGE" bash "$script")
trap 'podman rm -f "$cid" >/dev/null 2>&1 || true' EXIT
rc=''
for _ in $(seq 120); do
  if rc=$(podman wait "$cid" 2>/dev/null); then break; fi
  rc=''
  sleep 5
done
log=$(podman logs "$cid" 2>&1)
printf '%s\n' "$log"
[[ -n $rc ]] || { echo "error: lost track of test container $cid" >&2; exit 2; }
[[ $rc -eq 0 ]] || exit "$rc"
# The exit status alone was once 0 after a FAIL (a playbook killed by
# SIGTERM); the suite's own count is the authority.
summary=$(grep -E '^[0-9]+/[0-9]+ checks passed$' <<<"$log" | tail -1 || true)
if ! [[ $summary =~ ^([0-9]+)/([0-9]+)\ checks\ passed$ && ${BASH_REMATCH[1]} -eq ${BASH_REMATCH[2]} ]]; then
  echo "error: no 'N/N checks passed' line (got: '${summary}')" >&2
  exit 1
fi

# Keys that exist only in the initial network namespace, checked read-only in
# a container that shares the host's (no capabilities, nothing is written).
deferred=$(wc -l < "$out_dir/netns-only-keys" | tr -d ' ')
if [[ $deferred -gt 0 ]]; then
  podman run --rm --platform linux/amd64 --network=host --cap-drop=ALL \
    -v "$out_dir:/out:ro" "$IMAGE" sh -c '
      while read -r key; do
        [ -e "/proc/sys/$(echo "$key" | tr . /)" ] || { echo "FAIL: sysctl key $key missing in init netns" >&2; exit 1; }
      done < /out/netns-only-keys'
fi
echo "PASS: $deferred deferred net.* sysctl key(s) exist in the initial network namespace"
