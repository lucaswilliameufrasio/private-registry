#!/usr/bin/env bash
set -euo pipefail

# Isolated phase-0 fixture; same image supplies server, pg_dump and pg_restore.
image=postgres:18.6-alpine3.23@sha256:8c80c49c67052d82f9aaf4ee1f1881c8926b445a1cc916892934845eb8c24204
if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker pull "$image"
fi
