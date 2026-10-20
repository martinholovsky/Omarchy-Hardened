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

# NET_ADMIN/NET_RAW let ufw program netfilter inside the container.
exec podman run --rm --platform linux/amd64 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$repo_root:/src:ro" \
  "$IMAGE" bash /src/tests/container/inside.sh
