#!/usr/bin/env bash
set -euo pipefail

images=(
  ghcr.io/goauthentik/server@sha256:ab9b4e8cc4ab3f8d1198d2db6aeea66bafea1963b3f2843589e0d163f97d9849
  postgres:18.6-alpine3.23@sha256:8c80c49c67052d82f9aaf4ee1f1881c8926b445a1cc916892934845eb8c24204
  valkey/valkey:9.0.3-alpine@sha256:e1095c6c76ee982cb2d1e07edbb7fb2a53606630a1d810d5a47c9f646b708bf5
)

for image in "${images[@]}"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker pull "$image"
  fi
done
