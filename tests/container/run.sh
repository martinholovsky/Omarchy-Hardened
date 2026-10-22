#!/usr/bin/env bash
# Run the container-safe roles in a pinned Arch Linux image, against the PAM
# state Omarchy leaves behind, and check the result with tools independent of
# the roles themselves.
#
# Usage: tests/container/run.sh   (needs podman)
set -euo pipefail

# archlinux:base, multi-arch index digest, published 2026-10-19.
readonly IMAGE='docker.io/library/archlinux@sha256:e43f1fd80e073992c5f173efbbbf65144170bf60aeb7369940087d63eacea8f4'

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

command -v podman >/dev/null 2>&1 || { echo "error: podman is required" >&2; exit 2; }

out_dir="$repo_root/tests/container/.out"
rm -rf "$out_dir" && mkdir -p "$out_dir"

# NET_ADMIN/NET_RAW let ufw program netfilter inside the container.
# Run detached and wait in a retry loop: on macOS the client's API connection
# to the podman machine was seen to drop mid-run ("wait for container: EOF"),
# which killed an attached run although the container was fine.
cid=$(podman run -d --platform linux/amd64 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$repo_root:/src:ro" -v "$out_dir:/out" \
  "$IMAGE" bash /src/tests/container/inside.sh)
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
