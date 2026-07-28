#!/bin/sh
# Extract whole source files CREATED in AI-coauthored commits (Copilot/Claude).
# Writes samples to /samples/ai/<id>__<lang>.txt  (lang encoded in name).
set -e
mkdir -p /samples/ai
OUT=/samples/ai
N=0
TARGET=250
REPOS_TRIED=0
MAX_REPOS=60

while read repo; do
  [ -z "$repo" ] && continue
  REPOS_TRIED=$((REPOS_TRIED+1))
  [ $REPOS_TRIED -gt $MAX_REPOS ] && break
  [ $N -ge $TARGET ] && break
  d="/tmp/r$REPOS_TRIED"
  rm -rf "$d"
  # partial clone: commits + trees, blobs on demand; bounded depth
  if ! timeout 90 git clone --quiet --depth 120 --filter=blob:none "https://github.com/$repo.git" "$d" 2>/dev/null; then
    continue
  fi
  cd "$d" 2>/dev/null || continue
  # AI-coauthored commit SHAs
  shas=$(git log --grep='Co-authored-by: Copilot' --grep='Co-Authored-By: Claude' -i --format='%H' 2>/dev/null | head -40)
  for sha in $shas; do
    [ $N -ge $TARGET ] && break
    # files ADDED (created) in this commit, source extensions only
    files=$(git show --diff-filter=A --name-only --format='' "$sha" 2>/dev/null | grep -iE '\.(py|js|ts|go|java)$' | grep -viE '(test|spec|\.min\.|vendor/|node_modules/|\.d\.ts$)' | head -8)
    for fp in $files; do
      [ $N -ge $TARGET ] && break
      ext="${fp##*.}"
      case "$ext" in
        py) lang=python;; js) lang=javascript;; ts) lang=typescript;; go) lang=go;; java) lang=java;; *) continue;;
      esac
      content=$(git show "$sha:$fp" 2>/dev/null) || continue
      lc=$(printf '%s\n' "$content" | wc -l)
      [ "$lc" -lt 8 ] && continue
      [ "$lc" -gt 800 ] && continue
      printf '%s' "$content" > "$OUT/${N}__${lang}.txt"
      N=$((N+1))
    done
  done
  cd /
  rm -rf "$d"
done < /v/ai_repos.txt

echo "AI_SAMPLES_COLLECTED=$N (repos tried=$REPOS_TRIED)"
