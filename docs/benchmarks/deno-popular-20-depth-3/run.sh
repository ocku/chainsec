#!/bin/sh
# Reproduces the Deno/JSR benchmark. Each report records the selected package release.
# Package ranking: JSR dependentCount among selected popular @std packages (2026-08-10).
set -u

out_dir="docs/benchmarks/deno-popular-20-depth-3"
cache_dir=".chainsec-cache"
packages='@std/path @std/fs @std/fmt @std/cli @std/encoding @std/assert @std/http @std/yaml @std/async @std/dotenv @std/streams @std/crypto @std/collections @std/media-types @std/testing @std/semver @std/log @std/bytes @std/ulid @std/front-matter'

mkdir -p "$out_dir" "$cache_dir"
: > "$out_dir/exit-statuses.tsv"

for package in $packages; do
  slug=$(printf '%s' "$package" | tr '@/ ' '___')
  cargo run -- \
    remote scan "jsr:$package" \
    --max-depth 3 \
    --allow-unlocked \
    --cache "$cache_dir" \
    --format json \
    --output "$out_dir/$slug.json"
  status=$?
  printf '%s\t%s\n' "$package" "$status" >> "$out_dir/exit-statuses.tsv"
done
