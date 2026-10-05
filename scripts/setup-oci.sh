#!/usr/bin/env bash
set -euo pipefail

root=/tmp/opencode/private-registry-oci-tools
mkdir -p "$root"
if [[ ! -x "$root/registry" ]] || ! "$root/registry" --version | grep -q ' 3\.1\.2$'; then
  case $(go env GOHOSTARCH) in
    amd64) checksum=40df2224d410f72ae425c3371873b078bbdbda3b8b612be9571f0e6751f3acc8 ;;
    arm64) checksum=09d26f88d2c0f161bd1b8bfc6c123571cc3d291dcca8af5477b3cacc4ec95e73 ;;
    *) echo 'OCI fixture currently requires Linux amd64/arm64' >&2; exit 1 ;;
  esac
  [[ $(go env GOHOSTOS) == linux ]] || { echo 'OCI server fixture requires Linux' >&2; exit 1; }
  work=$(mktemp -d /tmp/opencode/private-registry-oci-setup-XXXXXX)
  trap 'rm -f "$work/archive.tar.gz" "$work/registry"; rmdir "$work"' EXIT
  curl --silent --show-error --fail --location --max-time 120 \
    -o "$work/archive.tar.gz" "https://github.com/distribution/distribution/releases/download/v3.1.2/registry_3.1.2_linux_$(go env GOHOSTARCH).tar.gz"
  printf '%s  %s\n' "$checksum" "$work/archive.tar.gz" | sha256sum --check --status
  tar -xzf "$work/archive.tar.gz" -C "$work" registry
  install -m 0755 "$work/registry" "$root/registry"
fi
if [[ ! -x "$root/oras" ]] || ! go version -m "$root/oras" | grep -q 'oras.land/oras.*v1.3.4'; then
  GOBIN="$root" GOMAXPROCS=${GOMAXPROCS:-4} go install oras.land/oras/cmd/oras@v1.3.4
fi
