#!/bin/sh
# Pass N6 Part C: CodeQL CLI on the HELD-OUT corpora, security-extended suite, default
# configuration. Our measurement harness, run by hand on OSI-licensed open-source
# corpora only (CodeQL's license). Source is never built except where the language
# requires it (Go autobuild).
#   usage: codeql_run.sh <name> <language> <source-dir> [build-mode]
set -e
CQ=/workspaces/_codeql/codeql/codeql
OUT=/workspaces/_n6codeql
name=$1; lang=$2; src=$3; mode=${4:-none}
mkdir -p $OUT
db=$OUT/db-$name
rm -rf "${db:?}"
if [ "$mode" = "skip" ]; then
  $CQ database create "$db" --language="$lang" --source-root="$src" --threads=2 --ram=2500 --overwrite >"$OUT/$name.create.log" 2>&1
else
  $CQ database create "$db" --language="$lang" --source-root="$src" --build-mode="$mode" --threads=2 --ram=2500 --overwrite >"$OUT/$name.create.log" 2>&1
fi
case $lang in
  javascript) pack=javascript ;;
  *) pack=$lang ;;
esac
$CQ database analyze "$db" "codeql/${pack}-queries:codeql-suites/${pack}-security-extended.qls" \
  --format=sarif-latest --output="$OUT/$name.sarif" --threads=2 --ram=2500 >"$OUT/$name.analyze.log" 2>&1
echo "ok $name $(python3 -c "import json;d=json.load(open('$OUT/$name.sarif'));print(sum(len(r['results']) for r in d['runs']), 'alerts')")"
