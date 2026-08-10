#!/bin/sh
# Reproduces the PyPI benchmark. Each report records the selected package release.
# Package ranking: https://hugovk.github.io/top-pypi-packages/ (30 days, 2026-08-01).
set -u

out_dir="docs/benchmarks/pypi-popular-20-depth-3"
cache_dir=".chainsec-cache"
packages='boto3 packaging typing-extensions certifi urllib3 idna requests charset-normalizer setuptools botocore cryptography cffi pluggy pygments pyyaml python-dateutil six aiobotocore numpy pycparser'

mkdir -p "$out_dir" "$cache_dir"
: > "$out_dir/exit-statuses.tsv"

for package in $packages; do
  slug=$(printf '%s' "$package" | tr '@/ ' '___')
  cargo run -- \
    --remote "pypi:$package" \
    --max-depth 3 \
    --allow-unlocked \
    --allow-host files.pythonhosted.org \
    --cache "$cache_dir" \
    --format json \
    --output "$out_dir/$slug.json"
  status=$?
  printf '%s\t%s\n' "$package" "$status" >> "$out_dir/exit-statuses.tsv"
done
