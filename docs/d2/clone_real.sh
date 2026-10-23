#!/bin/sh
# Shallow-fetch each real-repo precision corpus at its recorded commit into /workspaces/_p3/<name>.
# Source only: nothing is built, installed or run.
# usage: sh clone_real.sh <list>   (lines: name owner/repo[,fallback/repo] sha; docs/d2/real_commits.txt)
set -u
mkdir -p /workspaces/_p3
while read name slugs sha; do
  d=/workspaces/_p3/$name
  if [ -f "$d/.p3done" ]; then echo "have $name"; continue; fi
  ok=""
  for slug in $(echo "$slugs" | tr ',' ' '); do
    rm -rf "$d"; mkdir -p "$d"; cd "$d"
    if git init -q && git -c safe.directory='*' remote add origin "https://github.com/$slug.git" \
       && git -c safe.directory='*' fetch -q --depth 1 origin "$sha" \
       && git -c safe.directory='*' -c advice.detachedHead=false checkout -q FETCH_HEAD; then
      rm -rf .git; echo "$slug $sha" > .p3done; ok=1; echo "ok $name $slug $(du -sh . | cut -f1)"; cd /; break
    fi
    cd /
  done
  [ -n "$ok" ] || echo "FAIL $name"
done < "${1:-/p3/real_commits.txt}"
