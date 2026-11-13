#!/usr/bin/env bash
set -euo pipefail

# Mailpit is the development SMTP server: integration tests start it on
# loopback and read delivered messages through its HTTP API.
root=/tmp/opencode/private-registry-mailpit
version=v1.33.1
mkdir -p "$root"
if [[ ! -x "$root/mailpit" ]] || ! "$root/mailpit" version 2>/dev/null | grep -q "${version}"; then
  [[ $(go env GOHOSTOS) == linux ]] || { echo 'Mailpit fixture requires Linux' >&2; exit 1; }
  case $(go env GOHOSTARCH) in
    amd64) checksum=84d7fe375ebef25df26758984dc0d5d5e17d8c0734cb2e77be7873b14ab51716 ;;
    arm64) checksum=3c5f076cb676d6980e47da030861c6d60f1f5614103dea93cccbcdfc43198e12 ;;
    *) echo 'Mailpit fixture currently requires Linux amd64/arm64' >&2; exit 1 ;;
  esac
  mkdir -p /tmp/opencode
  work=$(mktemp -d /tmp/opencode/private-registry-mailpit-setup-XXXXXX)
  trap 'rm -rf "$work"' EXIT
  curl --silent --show-error --fail --location --max-time 120 \
    -o "$work/archive.tar.gz" "https://github.com/axllent/mailpit/releases/download/${version}/mailpit-linux-$(go env GOHOSTARCH).tar.gz"
  printf '%s  %s\n' "$checksum" "$work/archive.tar.gz" | sha256sum --check --status
  tar -xzf "$work/archive.tar.gz" -C "$work" mailpit
  install -m 0755 "$work/mailpit" "$root/mailpit"
fi
"$root/mailpit" version
