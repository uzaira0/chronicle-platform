#!/usr/bin/env bash
set -euo pipefail

server_dir=chronicle-server
migrations=src/main/resources/db/migration
fail() { printf 'FAIL setup: %s\n' "$*" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --server-dir)
      if (($# < 2)) || [[ -z "$2" ]]; then fail "$1 requires a value"; fi
      server_dir=$2
      shift 2 ;;
    -h|--help)
      printf 'Usage: %s [--server-dir chronicle-server]\n' "$0"
      exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done
cd "$server_dir" || fail "cannot open server directory: $server_dir"
[[ -d "$migrations" ]] || fail "missing $migrations"
shopt -s nullglob
migrations_files=("$migrations"/*.sql)
((${#migrations_files[@]})) || fail "no SQL migrations"

additive=PASS
numbering=PASS
# Flyway compares versions numerically part by part, so leading zeroes, trailing .0 parts and
# underscore/dot separators do not make a different version (V1, V1.0 and V01_0 are one).
duplicates=$(for file in "${migrations_files[@]}"; do
  name=${file##*/}
  [[ "$name" == V*__*.sql ]] || continue
  version=${name#V}; version=${version%%__*}
  awk -v v="$version" 'BEGIN { n=split(v,p,/[._]/); out=""
    for (i=1; i<=n; i++) { sub(/^0+/, "", p[i]); out = out (i>1 ? "." : "") (p[i] == "" ? "0" : p[i]) }
    sub(/(\.0)+$/, "", out); print out }'
done | sort | uniq -d)
if [[ -n "$duplicates" ]]; then
  numbering=FAIL
  while IFS= read -r version; do
    printf 'FAIL numbering: duplicate version V%s among migrations\n' "$version"
  done <<< "$duplicates"
fi
for file in "${migrations_files[@]}"; do
  [[ "$file" == *.sql ]] || continue
  if [[ ! -f "$file" || -L "$file" ]]; then
    printf 'FAIL additive-only: %s:1: migration must be a regular SQL file\n' "$file"
    additive=FAIL
    continue
  fi
  # Byte-based scan: the keywords are ASCII, and a UTF-8 locale makes BSD awk abort on valid UTF-8.
  if ! LC_ALL=C awk '
    function hit(line, reason) {
      printf "%s additive-only: %s:%d: %s%s\n", approved ? "PASS" : "FAIL", FILENAME, line, reason, approved ? " (approved: " approval ")" : ""
      if (!approved) failed = 1
    }
    function statement(words,lines,n,   i,j,reason,has_where,depth) {
      for (i=1; i<=n; i++) {
        reason = ""
        # Every DROP needs approval: schemas, extensions, types and sequences cascade into data.
        if (words[i] == "DROP")
          reason = "DROP " words[i+1]
        else if (words[i] == "TRUNCATE") reason = "TRUNCATE"
        else if (words[i] == "RENAME" && words[i+1] ~ /^(TO|COLUMN)$/)
          reason = "RENAME " words[i+1]
        else if (words[i] == "ALTER" && words[i+1] == "COLUMN") {
          for (j=i+2; j<=n && words[j] != ","; j++)
            if (words[j] == "TYPE") { reason = "ALTER COLUMN ... TYPE"; break }
        } else if (words[i] == "DELETE" && words[i+1] == "FROM") {
          has_where = 0; depth = 0
          for (j=i+2; j<=n; j++) {
            if (words[j] == "(") depth++
            if (words[j] == ")") { if (!depth) break; depth-- }
            if (words[j] == "WHERE" && !depth) has_where = 1
          }
          if (!has_where) reason = "DELETE FROM without WHERE"
        }
        if (reason != "") hit(lines[i], reason)
      }
      delete words; delete lines
    }
    # Conservatively check SQL text in string literals too (e.g. EXECUTE SQL).
    # Keep its WHERE tokens separate from the containing statement.
    function literal_sql(text,line,   tokens,locations,count,c,t) {
      while (length(text)) {
        c=substr(text,1,1)
        if (c == "\n") line++
        if (match(text, /^[A-Za-z_0-9]+/)) {
          t=substr(text,1,RLENGTH); text=substr(text,RLENGTH+1)
          tokens[++count]=toupper(t); locations[count]=line
          continue
        }
        if (c == ";") { statement(tokens,locations,count); count=0 }
        else if (c !~ /[[:space:]]/) { tokens[++count]=c; locations[count]=line }
        text=substr(text,2)
      }
      statement(tokens,locations,count)
    }
    function token() {
      if (word != "") { words[++n] = toupper(word); lines[n] = wordline; word = "" }
    }
    BEGIN { header = 1; quote = sprintf("%c", 39) }
    {
      # Only a real leading line comment, before SQL, can record approval.
      if (header && !block && !quoted && $0 ~ /^[[:space:]]*-- chronicle:destructive-approved[[:space:]]+[^[:space:]]/) {
        approved = 1; approval = $0
        sub(/^[[:space:]]*-- chronicle:destructive-approved[[:space:]]+/, "", approval)
      }
      for (p=1; p<=length($0); p++) {
        c = substr($0,p,1); pair = substr($0,p,2)
        if (block) {
          if (pair == "/*") { block++; p++ }
          else if (pair == "*/") { block--; p++ }
          continue
        }
        if (quoted) {
          if (c == quoted) {
            if (substr($0,p+1,1) == quoted) { literal = literal c; p++ }
            else {
              if (quoted == quote) literal_sql(literal,literal_line)
              quoted = ""
            }
          } else literal = literal c
          continue
        }
        if (pair == "--") { token(); break }
        if (pair == "/*") { token(); block++; p++; continue }
        if (c ~ /[[:space:]]/) { token(); continue }
        header = 0
        if (c == quote || c == "\"") {
          token(); quoted = c; literal = ""; literal_line = NR
          words[++n] = "<quoted>"; lines[n] = NR; continue
        }
        # Dollar-quoted function bodies are scanned as SQL, including their statements.
        if (c == "$" && match(substr($0,p), /^\$([A-Za-z_][A-Za-z_0-9]*)?\$/)) {
          token(); p += RLENGTH-1; continue
        }
        if (c ~ /[A-Za-z_0-9]/) {
          if (word == "") wordline = NR
          word = word c
        } else {
          token()
          if (c == ";") { statement(words,lines,n); n=0 }
          else { words[++n] = c; lines[n] = NR }
        }
      }
      token()
      if (quoted) literal = literal "\n"
    }
    END {
      statement(words,lines,n)
      if (block || quoted) {
        printf "FAIL additive-only: %s:%d: unterminated SQL comment or quote\n", FILENAME, NR
        failed = 1
      }
      exit failed
    }
  ' "$file"; then additive=FAIL; fi

  if [[ ! "${file##*/}" =~ ^V[0-9]+([._][0-9]+)*__.+\.sql$ ]]; then
    printf 'FAIL numbering: %s: invalid versioned migration name\n' "$file"
    numbering=FAIL
  fi
done
printf '%s additive-only (b)\n' "$additive"
printf '%s numbering (c)\n' "$numbering"
[[ "$additive" == PASS && "$numbering" == PASS ]]
