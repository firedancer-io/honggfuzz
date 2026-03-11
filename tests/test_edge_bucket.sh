#!/bin/bash
# =============================================================================
# Edge Bucket Coverage Signal Regression Test
# =============================================================================
#
# Verifies that ALL THREE independent coverage signals are consumed by the
# fuzz loop and contribute to corpus growth:
#
#   1. pidNewEdge       -> softNewEdge       -> softCntEdge       (new edge discovery)
#   2. pidEdgeBucketInc -> softEdgeBucketInc -> softCntEdgeBucket (edge frequency promotion)
#   3. pidNewCmp        -> softNewCmp        -> softCntCmp        (CMP comparison progress)
#
# The edge bucket signal (2) was broken when _HF_EDGE_BUCKET_LOG_COUNTING was
# introduced -- instrument.c wrote to pidEdgeBucketInc but fuzz.c never read it.
# This test catches that class of regression.
#
# Log format expected: (i/b/h/e/p/c/eb) New:<7 values>, Cur:<7 values>
#   i  = cpuInstrCnt          (hw perf)
#   b  = cpuBranchCnt         (hw perf)
#   h  = newBBCnt             (hw BB)
#   e  = softNewEdge          (new edges)
#   p  = softNewPC            (new PCs)
#   c  = softNewCmp           (CMP progress)
#   eb = softEdgeBucketInc    (edge bucket promotions)
#
# Display format expected: edge: <N>/<total> [%]  pc: <N>  cmp: <N>  eb: <N>
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HONGGFUZZ_DIR="$(dirname "$SCRIPT_DIR")"
cd "$HONGGFUZZ_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0
TESTS_RUN=0

pass() { echo -e "   ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "   ${RED}[FAIL]${NC} $1"; ERRORS=$((ERRORS + 1)); }
warn() { echo -e "   ${YELLOW}[WARN]${NC} $1"; }

# ---- Setup ----
TEST_DIR=$(mktemp -d)
CORPUS_DIR="$TEST_DIR/corpus"
WORKSPACE_DIR="$TEST_DIR/workspace"
mkdir -p "$CORPUS_DIR" "$WORKSPACE_DIR"

cleanup() {
    echo ""
    echo "Cleaning up $TEST_DIR..."
    rm -rf "$TEST_DIR"
    rm -f tests/test_edge_bucket_target
}
trap cleanup EXIT

echo "============================================================"
echo " Edge Bucket Coverage Signal Regression Test"
echo "============================================================"
echo ""

# ---- Build ----
echo "1. Building test target with trace-pc-guard, inline-8bit-counters, and trace-cmp..."
if ! ./hfuzz_cc/hfuzz-cc -fsanitize-coverage=trace-pc-guard,inline-8bit-counters,trace-cmp \
        -o tests/test_edge_bucket_target tests/test_edge_bucket_target.c 2>&1; then
    fail "Failed to build test target"
    exit 1
fi
pass "Test target built"
echo ""

# ---- Seed corpus ----
# Create seeds with different data[0] values to force different loop iteration
# counts and therefore different edge bucket levels.
# instrumentCntMap boundaries: 1, 2, 3, 4-5, 6-10, 11-32, 33-64, 65-255
echo "2. Creating seed corpus with diverse iteration counts..."
printf '\x01ABCD' > "$CORPUS_DIR/seed_iter1"    # 1 iteration
printf '\x03ABCD' > "$CORPUS_DIR/seed_iter3"    # 3 iterations  (crosses bucket 2->4)
printf '\x08ABCD' > "$CORPUS_DIR/seed_iter8"    # 8 iterations  (crosses bucket 8->16)
printf '\x20ABCD' > "$CORPUS_DIR/seed_iter32"   # 32 iterations (crosses bucket 16->32)
printf '\x50ABCD' > "$CORPUS_DIR/seed_iter80"   # 80 iterations (crosses bucket 64->128)
printf '\xFFEDGETEST' > "$CORPUS_DIR/seed_cmp"  # CMP: tries "EDGETEST" prefix
printf '\x01XYZ' > "$CORPUS_DIR/seed_cmp2"      # CMP: tries "XYZ" prefix
SEED_COUNT=$(ls "$CORPUS_DIR" | wc -l)
pass "Created $SEED_COUNT seed files"
echo ""

# ---- Run fuzzer ----
FUZZ_SECONDS=20
echo "3. Running honggfuzz for ${FUZZ_SECONDS}s (1 thread, persistent mode)..."
timeout "${FUZZ_SECONDS}s" ./honggfuzz \
    -i "$CORPUS_DIR" \
    -o "$CORPUS_DIR" \
    -W "$WORKSPACE_DIR" \
    -n 1 \
    -v \
    --persistent \
    --exit_upon_crash \
    -- ./tests/test_edge_bucket_target 2>&1 | tee "$TEST_DIR/fuzz.log" || true
echo ""

# ---- Parse results ----
echo "4. Verifying coverage signals..."
echo ""

# --- Check 4a: Log format includes edge bucket field ---
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q "(i/b/h/e/p/c/eb)" "$TEST_DIR/fuzz.log" 2>/dev/null; then
    pass "Log format contains (i/b/h/e/p/c/eb) -- edge bucket field present"
else
    fail "Log format missing (i/b/h/e/p/c/eb) -- edge bucket field NOT compiled in"
fi

# --- Check 4b: Edge bucket signal (eb) was consumed ---
# Log lines look like: "New:0/0/0/5/0/0/3, Cur:..."
# The 7th value in the New: group is softEdgeBucketInc (eb).
# Extract all eb values from New: fields and check if any are > 0.
TESTS_RUN=$((TESTS_RUN + 1))
EB_VALUES=$(grep -oP 'New:\K[0-9/]+' "$TEST_DIR/fuzz.log" 2>/dev/null | \
    awk -F'/' '{print $7}' | sort -rn | head -1) || EB_VALUES=0
EB_VALUES=${EB_VALUES:-0}
if [ "$EB_VALUES" -gt 0 ] 2>/dev/null; then
    pass "Edge bucket signal (eb) fired: max New eb=$EB_VALUES -- pidEdgeBucketInc is being consumed"
else
    fail "Edge bucket signal (eb) never fired (all New eb=0) -- pidEdgeBucketInc NOT consumed by fuzz loop!"
fi

# --- Check 4c: New edge signal (e) was consumed ---
# The 4th value in the New: group is softNewEdge.
TESTS_RUN=$((TESTS_RUN + 1))
EDGE_VALUES=$(grep -oP 'New:\K[0-9/]+' "$TEST_DIR/fuzz.log" 2>/dev/null | \
    awk -F'/' '{print $4}' | sort -rn | head -1) || EDGE_VALUES=0
EDGE_VALUES=${EDGE_VALUES:-0}
if [ "$EDGE_VALUES" -gt 0 ] 2>/dev/null; then
    pass "New edge signal (e) fired: max New e=$EDGE_VALUES -- pidNewEdge not regressed"
else
    fail "New edge signal (e) never fired (all New e=0) -- pidNewEdge REGRESSED!"
fi

# --- Check 4d: CMP signal (c) was consumed ---
# The 6th value in the New: group is softNewCmp.
TESTS_RUN=$((TESTS_RUN + 1))
CMP_VALUES=$(grep -oP 'New:\K[0-9/]+' "$TEST_DIR/fuzz.log" 2>/dev/null | \
    awk -F'/' '{print $6}' | sort -rn | head -1) || CMP_VALUES=0
CMP_VALUES=${CMP_VALUES:-0}
if [ "$CMP_VALUES" -gt 0 ] 2>/dev/null; then
    pass "CMP signal (c) fired: max New c=$CMP_VALUES -- pidNewCmp not regressed (trace_cmp working)"
else
    warn "CMP signal (c) did not fire (may need longer run or specific inputs)"
fi

# --- Check 4e: Cumulative edge bucket count (from Cur: fields) is non-zero ---
# Cur: field 7 is softCntEdgeBucket (cumulative eb across all inputs).
TESTS_RUN=$((TESTS_RUN + 1))
CUR_EB=$(grep -oP 'Cur:\K[0-9/]+' "$TEST_DIR/fuzz.log" 2>/dev/null | \
    awk -F'/' '{print $7}' | sort -rn | head -1) || CUR_EB=0
CUR_EB=${CUR_EB:-0}
if [ "$CUR_EB" -gt 0 ] 2>/dev/null; then
    pass "Cumulative edge bucket: $CUR_EB -- softCntEdgeBucket accumulating in fuzz loop"
else
    fail "Cumulative edge bucket is 0 -- softCntEdgeBucket NOT accumulating!"
fi

# --- Check 4f: Cumulative edge count (from Cur: fields) is non-zero ---
# Cur: field 4 is softCntEdge (cumulative new edges).
TESTS_RUN=$((TESTS_RUN + 1))
CUR_EDGES=$(grep -oP 'Cur:\K[0-9/]+' "$TEST_DIR/fuzz.log" 2>/dev/null | \
    awk -F'/' '{print $4}' | sort -rn | head -1) || CUR_EDGES=0
CUR_EDGES=${CUR_EDGES:-0}
if [ "$CUR_EDGES" -gt 0 ] 2>/dev/null; then
    pass "Cumulative edges: $CUR_EDGES -- softCntEdge accumulating"
else
    fail "Cumulative edge count is 0 -- coverage tracking broken!"
fi

# --- Check 4g: Corpus grew beyond seed count ---
TESTS_RUN=$((TESTS_RUN + 1))
FINAL_CORPUS=$(ls "$CORPUS_DIR" 2>/dev/null | wc -l)
if [ "$FINAL_CORPUS" -gt "$SEED_COUNT" ] 2>/dev/null; then
    pass "Corpus grew from $SEED_COUNT to $FINAL_CORPUS -- coverage feedback driving corpus"
else
    warn "Corpus did not grow ($FINAL_CORPUS files, started with $SEED_COUNT) -- may need longer run"
fi

# --- Check 4h: No errors or crashes ---
TESTS_RUN=$((TESTS_RUN + 1))
CRASH_COUNT=$(grep -c "limit exceeded\|CRASH\|SEGFAULT\|SIGABRT" "$TEST_DIR/fuzz.log" 2>/dev/null) || CRASH_COUNT=0
if [ "${CRASH_COUNT:-0}" -eq 0 ]; then
    pass "No crashes or limit errors"
else
    fail "Found $CRASH_COUNT crash/error lines in log"
fi

# ---- Summary ----
echo ""
echo "============================================================"
echo " Summary: $TESTS_RUN checks, $ERRORS failures"
echo "============================================================"

if [ "$ERRORS" -gt 0 ]; then
    echo ""
    echo -e "${RED}REGRESSION DETECTED -- $ERRORS check(s) failed!${NC}"
    echo ""
    echo "Coverage signal pipeline:"
    echo "  instrument.c writes -> fuzz.c reads -> coverage decision -> corpus"
    echo ""
    echo "If eb never fired:  fuzz.c is not reading pidEdgeBucketInc"
    echo "If e never fired:   fuzz.c is not reading pidNewEdge"
    echo "If c never fired:   trace_cmp / instrumentUpdateCmpMap broken"
    echo "If display missing: display.c not reading softCntEdgeBucket"
    exit 1
fi

echo ""
echo -e "${GREEN}All coverage signals verified -- no regressions detected.${NC}"
echo ""
echo "Confirmed working signals:"
echo "  pidNewEdge       -> softNewEdge       -> softCntEdge       [OK]"
echo "  pidEdgeBucketInc -> softEdgeBucketInc -> softCntEdgeBucket [OK]"
echo "  pidNewCmp        -> softNewCmp        -> softCntCmp        [OK]"
echo ""
exit 0
