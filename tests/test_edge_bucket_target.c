/*
 * Test target for verifying edge bucket coverage feedback.
 *
 * This harness is designed to trigger all three coverage signals:
 *   1. pidNewEdge       - first-time edge discovery (new code path)
 *   2. pidEdgeBucketInc - edge frequency bucket promotion (same edge, more hits)
 *   3. pidNewCmp        - CMP comparison progress (trace_cmp instrumentation)
 *
 * The instrumentCntMap bucket boundaries are:
 *   hits 0->0, 1->1, 2->2, 3->4, 4-5->8, 6-10->16, 11-32->32, 33-64->64, 65-255->128
 * So iterating a loop body {1, 2, 3, 5, 8, 20, 50, 100} times crosses every bucket.
 *
 * Compile: hfuzz_cc/hfuzz-cc -fsanitize-coverage=trace-pc-guard,trace-cmp \
 *              -o tests/test_edge_bucket_target tests/test_edge_bucket_target.c
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Signal 2: pidEdgeBucketInc
 * A tight loop whose iteration count is controlled by input.
 * Different inputs cause different hit counts on the same edges,
 * promoting them through instrumentCntMap buckets (1->2->4->8->...).
 * Each promotion fires pidEdgeBucketInc (with log probability).
 */
static volatile int g_sink;

static void exercise_loop(unsigned iters) {
    volatile int acc = 0;
    for (unsigned i = 0; i < iters; i++) {
        acc += i;          /* edges in this loop body get hit `iters` times */
        if (i & 1) acc--;  /* extra branch for more edges per iteration */
    }
    g_sink = acc;
}

/*
 * Signal 1: pidNewEdge
 * Branchy code that discovers new edges depending on input bytes.
 * Each unique combination of branch outcomes is a new edge.
 */
static int exercise_branches(const uint8_t* data, size_t len) {
    int r = 0;
    if (len > 2) {
        if (data[1] < 64)       r += 1;
        else if (data[1] < 128) r += 2;
        else if (data[1] < 192) r += 3;
        else                    r += 4;

        if (data[2] & 0x01) r += 10;
        if (data[2] & 0x02) r += 20;
        if (data[2] & 0x04) r += 40;
        if (data[2] & 0x08) r += 80;
    }
    return r;
}

/*
 * Signal 3: pidNewCmp  (via instrumentUpdateCmpMap / trace_cmp)
 * Multi-byte comparisons that the fuzzer can solve byte-by-byte.
 * Each byte of progress increments pidNewCmp independently of edge buckets.
 */
static int exercise_cmp(const uint8_t* data, size_t len) {
    if (len >= 4 && memcmp(data, "EDGE", 4) == 0) {
        if (len >= 8 && memcmp(data + 4, "TEST", 4) == 0) {
            return 999;
        }
        return 100;
    }
    if (len >= 3 && data[0] == 'X' && data[1] == 'Y' && data[2] == 'Z') {
        return 50;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len) {
    if (len < 1) return 0;

    /* data[0] controls loop iterations -> forces bucket promotions.
     * Different values cross different instrumentCntMap boundaries:
     *   1=bucket0->1, 2=1->2, 3=2->4, 5=4->8, 8=8->16, 20=16->32, 50=32->64, 100=64->128
     */
    exercise_loop((unsigned)data[0]);

    /* Remaining bytes exercise new-edge and CMP signals */
    exercise_branches(data, len);
    exercise_cmp(data, len);

    return 0;
}
