#!/bin/sh
# Sample whole source files from PRE-2020 tags of established repos — guaranteed
# pre-LLM (Copilot GA was 2022; GPT-3 mid-2020). Writes /samples/human/<id>__<lang>.txt
set -e
mkdir -p /samples/human
OUT=/samples/human
N=0
TARGET=230

# repo|tag(pre-2020)|ext|lang|srcdir
set -- \
  "django/django|2.0|py|python|django" \
  "pallets/flask|1.0|py|python|flask" \
  "psf/requests|v2.21.0|py|python|requests" \
  "pallets/click|7.0|py|python|click" \
  "expressjs/express|4.16.4|js|javascript|lib" \
  "gin-gonic/gin|v1.4.0|go|go|." \
  "spf13/cobra|v0.0.5|go|go|." \
  "google/gson|gson-parent-2.8.5|java|java|gson/src/main"

for spec in "$@"; do
  [ $N -ge $TARGET ] && break
  repo=$(echo "$spec" | cut -d'|' -f1)
  tag=$(echo "$spec" | cut -d'|' -f2)
  ext=$(echo "$spec" | cut -d'|' -f3)
  lang=$(echo "$spec" | cut -d'|' -f4)
  src=$(echo "$spec" | cut -d'|' -f5)
  d="/tmp/h_$(echo $repo | tr '/' '_')"
  rm -rf "$d"
  if ! timeout 120 git clone --quiet --depth 1 --branch "$tag" "https://github.com/$repo.git" "$d" 2>/dev/null; then
    echo "clone failed: $repo@$tag"; continue
  fi
  # up to ~32 source files from this repo's source dir
  found=$(find "$d/$src" -name "*.$ext" 2>/dev/null | grep -viE '(test|spec|/vendor/|node_modules|__pycache__)' | head -60)
  cnt=0
  for fp in $found; do
    [ $N -ge $TARGET ] && break
    [ $cnt -ge 32 ] && break
    lc=$(wc -l < "$fp" 2>/dev/null || echo 0)
    [ "$lc" -lt 8 ] && continue
    [ "$lc" -gt 800 ] && continue
    cp "$fp" "$OUT/${N}__${lang}.txt"
    N=$((N+1)); cnt=$((cnt+1))
  done
  echo "$repo@$tag -> +$cnt (total $N)"
  rm -rf "$d"
done
echo "HUMAN_SAMPLES_COLLECTED=$N"
