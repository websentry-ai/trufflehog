#!/usr/bin/env bash
set -euo pipefail

version=0.169.1
asset=codex-x86_64-unknown-linux-musl
sha256=bd8383e0eaf3e4ca2aa5628f91ed9456bc3392d26134a04e949f47d7ef3660c1
install_dir=$(mktemp -d "${RUNNER_TEMP}/dlp-codex.XXXXXXXX")
cd "$install_dir"
curl --fail --silent --show-error --location --retry 3 \
  "https://github.com/openai/codex/releases/download/rust-v${version}/${asset}.tar.gz" -o codex.tar.gz
printf '%s  codex.tar.gz\n' "$sha256" | sha256sum --check
tar -xzf codex.tar.gz "$asset"
mv "$asset" codex
./codex --version
printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
