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
podman run --rm --platform linux/amd64 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$repo_root:/src:ro" -v "$out_dir:/out" \
  "$IMAGE" bash /src/tests/container/inside.sh

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
