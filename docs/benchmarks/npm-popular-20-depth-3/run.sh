#!/bin/sh
# Reproduces the npm benchmark. Each report records the selected package release.
set -u

out_dir="docs/benchmarks/npm-popular-20-depth-3"
cache_dir=".chainsec-cache"
packages='@types/node typescript lodash react chalk debug semver glob minimist ms yargs commander axios express eslint webpack jest next vue uuid'

mkdir -p "$out_dir" "$cache_dir"
: > "$out_dir/exit-statuses.tsv"

for package in $packages; do
  slug=$(printf '%s' "$package" | tr '@/ ' '___')
  cargo run -- \
    --remote "npm:$package" \
    --max-depth 3 \
    --allow-unlocked \
    --cache "$cache_dir" \
    --format json \
    --output "$out_dir/$slug.json"
  status=$?
  printf '%s\t%s\n' "$package" "$status" >> "$out_dir/exit-statuses.tsv"
done
