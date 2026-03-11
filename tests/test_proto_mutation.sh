#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

ITERATIONS="${1:-50000}"
BINARY="test_proto_mutation"

echo "============================================================"
echo " Proto/Flatbuf Mutation Validation"
echo "============================================================"
echo ""

echo "1. Building test..."
if ! gcc -std=gnu17 -O2 -Wall -Wextra -Werror \
        -o "$BINARY" test_proto_mutation.c 2>&1; then
    echo -e "${RED}Build failed${NC}"
    exit 1
fi
echo -e "   ${GREEN}[OK]${NC} Built $BINARY"
echo ""

echo "2. Running tests ($ITERATIONS parse-rate iterations)..."
echo ""

if ./"$BINARY" "$ITERATIONS"; then
    echo -e "${GREEN}All tests passed.${NC}"
    RETVAL=0
else
    echo -e "${RED}Some tests failed!${NC}"
    RETVAL=1
fi

rm -f "$BINARY"
exit $RETVAL
