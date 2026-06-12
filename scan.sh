#!/usr/bin/env bash
# CC Powerpack — CI secret scan. Scans tracked files for credential-shaped strings
# and flags sensitive filenames. Part of cc-powerpack (github.com/Ludoonus/cc-powerpack).
set -uo pipefail
FAIL="${1:-true}"
patterns='(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----)'
found=0

# 1. credential-shaped strings in tracked files
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if grep -aEl "$patterns" "$f" >/dev/null 2>&1; then
    echo "::error file=$f::cc-powerpack: credential-shaped string detected"
    found=1
  fi
done < <(git ls-files 2>/dev/null)

# 2. sensitive filenames tracked in the repo
if git ls-files 2>/dev/null | grep -qE '(^|/)(\.env(\..+)?|id_rsa|id_ed25519|.*\.pem|.*\.p12|credentials\.json)$'; then
  echo "::error::cc-powerpack: a sensitive file (.env / key material) is tracked in the repo"
  found=1
fi

if [ "$found" = "1" ]; then
  echo "cc-powerpack: secrets/sensitive files found. Remove and rotate."
  [ "$FAIL" = "true" ] && exit 1
else
  echo "cc-powerpack: no secrets or sensitive files detected. ✓"
fi
