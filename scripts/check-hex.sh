#!/usr/bin/env bash
set -euo pipefail

if ! command -v mix >/dev/null 2>&1; then
	printf '%s\n' 'Mix/Elixir is required for the Hex integration fixture.' >&2
	exit 1
fi

info="$(mix hex.info)"
for expected in 'Hex:    2.5.1' 'Elixir: 1.19.5' 'OTP:    28.4'; do
	if [[ "$info" != *"$expected"* ]]; then
		printf '%s\n' "$info" >&2
		printf 'Expected pinned Hex test toolchain: %s\n' "$expected" >&2
		exit 1
	fi
done

printf '%s\n' "$info"
