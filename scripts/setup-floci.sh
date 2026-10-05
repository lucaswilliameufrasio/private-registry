#!/usr/bin/env bash
set -euo pipefail

# Pinned development emulator. The suite never mounts the Docker socket into it.
image=floci/floci:2.1.0@sha256:f5aa8c18302cedb4f2385f5c4e455b3efc77fee6bf7b6e5d1712b2817ba102db
if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker pull "$image"
fi
