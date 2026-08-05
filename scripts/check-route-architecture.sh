#!/usr/bin/env bash
# Architecture check: ensure route files never access secret store namespaces.
#
# Route files (route/files/**/*.rs) are the public-facing surface. They must
# only access the "state" namespace, never "secrets". The SIWE session is
# stored via the Host trait which goes through the SDK, not direct store keys.
set -euo pipefail

ROUTE_FILES_DIR="route/files"
VIOLATIONS=0

# Check that no route file references secret namespace paths.
while IFS= read -r -d '' file; do
    if grep -q 'secrets/' "$file"; then
        echo "ERROR: $file references a 'secrets/' path"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
    if grep -q 'secret_namespaces' "$file"; then
        echo "ERROR: $file references 'secret_namespaces'"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done < <(find "$ROUTE_FILES_DIR" -name '*.rs' -print0)

# Check that route files don't directly call sign_hash (must go through crate API).
while IFS= read -r -d '' file; do
    if grep -q 'sign_hash\|sign_hashes' "$file"; then
        echo "ERROR: $file calls sign_hash directly — signing must go through the crate API"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done < <(find "$ROUTE_FILES_DIR" -name '*.rs' -print0)

# Check that route files don't construct SignRequest directly.
while IFS= read -r -d '' file; do
    if grep -q 'SignRequest' "$file"; then
        echo "ERROR: $file constructs SignRequest — must use crate API"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done < <(find "$ROUTE_FILES_DIR" -name '*.rs' -print0)

if [ "$VIOLATIONS" -gt 0 ]; then
    echo ""
    echo "Architecture check FAILED: $VIOLATIONS violation(s) found."
    exit 1
fi

echo "Architecture check passed: route files are clean."
