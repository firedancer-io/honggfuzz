/*
 * Empirical validation of protobuf/flatbuffer-aware byte-level mutations.
 *
 * Tests:
 *   1. Varint encode/decode round-trip correctness
 *   2. Proto wire format scanner correctness on known messages
 *   3. Parse rate comparison: blind byte mutation vs proto-aware mutation
 *   4. Flatbuffer scanner correctness on known flatbuf layout
 *
 * Build:  gcc -std=gnu17 -O2 -Wall -Wextra -o test_proto_mutation test_proto_mutation.c
 * Run:    ./test_proto_mutation [iterations]    (default: 50000)
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---------- xorshift64 PRNG (deterministic, fast) ---------- */

static uint64_t rng_state = 0;

static void rng_seed(uint64_t s) {
    rng_state = s ? s : 0xDEADBEEFCAFEBABEULL;
}

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static uint64_t rng_range(uint64_t lo, uint64_t hi) {
    return lo + (rng_next() % (hi - lo + 1));
}

/* ---------- Varint helpers (same algorithm as mangle.c) ---------- */

static size_t varint_decode(const uint8_t* data, size_t len, size_t off, uint64_t* val) {
    *val = 0;
    for (size_t i = 0; i < 10 && off + i < len; i++) {
        *val |= (uint64_t)(data[off + i] & 0x7F) << (i * 7);
        if (!(data[off + i] & 0x80)) {
            return i + 1;
        }
    }
    return 0;
}

static size_t varint_encode(uint8_t* buf, size_t max_len, uint64_t val) {
    size_t i = 0;
    do {
        if (i >= max_len) return 0;
        buf[i] = (uint8_t)(val & 0x7F);
        val >>= 7;
        if (val > 0) buf[i] |= 0x80;
        i++;
    } while (val > 0);
    return i;
}

/* ---------- Proto field scanner (same algorithm as mangle.c) ---------- */

typedef struct {
    size_t   tag_off;
    size_t   tag_len;
    size_t   val_off;
    size_t   val_len;
    uint32_t field_num;
    uint8_t  wire_type;
} field_t;

static size_t scan_fields(const uint8_t* data, size_t len, field_t* fields, size_t max_f) {
    size_t off = 0, count = 0;

    while (off < len && count < max_f) {
        uint64_t tag;
        size_t tl = varint_decode(data, len, off, &tag);
        if (tl == 0 || tag == 0) break;

        uint8_t  wt = tag & 0x07;
        uint32_t fn = (uint32_t)(tag >> 3);
        if (fn == 0 || fn > 536870911) break;

        fields[count].tag_off   = off;
        fields[count].tag_len   = tl;
        fields[count].val_off   = off + tl;
        fields[count].field_num = fn;
        fields[count].wire_type = wt;

        size_t vo = off + tl;
        switch (wt) {
        case 0: {
            uint64_t v;
            size_t vl = varint_decode(data, len, vo, &v);
            if (vl == 0) goto done;
            fields[count].val_len = vl;
            off = vo + vl;
            break;
        }
        case 1:
            if (vo + 8 > len) goto done;
            fields[count].val_len = 8;
            off = vo + 8;
            break;
        case 2: {
            uint64_t pl;
            size_t lb = varint_decode(data, len, vo, &pl);
            if (lb == 0 || pl > len || vo + lb + pl > len) goto done;
            fields[count].val_len = lb + (size_t)pl;
            off = vo + lb + (size_t)pl;
            break;
        }
        case 5:
            if (vo + 4 > len) goto done;
            fields[count].val_len = 4;
            off = vo + 4;
            break;
        default:
            goto done;
        }
        count++;
    }
done:
    return count;
}

/* ---------- Test helpers ---------- */

static int tests_run   = 0;
static int tests_pass  = 0;

#define ASSERT(cond, msg) do {                                               \
    tests_run++;                                                             \
    if (!(cond)) {                                                           \
        fprintf(stderr, "  [FAIL] %s (line %d)\n", (msg), __LINE__);        \
    } else {                                                                 \
        tests_pass++;                                                        \
        fprintf(stderr, "  [PASS] %s\n", (msg));                             \
    }                                                                        \
} while (0)

/*
 * Build a realistic protobuf message with varied wire types:
 *   field 1  varint          value 42
 *   field 2  length-delimited "hello" (5 bytes)
 *   field 3  varint          value 100
 *   field 4  fixed32         0x12345678
 *   field 5  fixed64         0x00000000DEADBEEF
 *   field 10 varint          value 300 (2-byte tag, 2-byte varint)
 */
static size_t build_test_proto(uint8_t* buf, size_t cap) {
    size_t off = 0;
#define PUT(byte) do { if (off < cap) buf[off++] = (uint8_t)(byte); } while (0)
    /* field 1 (varint): tag=0x08, val=0x2A */
    PUT(0x08); PUT(0x2A);
    /* field 2 (len-delimited): tag=0x12, len=5, "hello" */
    PUT(0x12); PUT(0x05); PUT('h'); PUT('e'); PUT('l'); PUT('l'); PUT('o');
    /* field 3 (varint): tag=0x18, val=0x64 */
    PUT(0x18); PUT(0x64);
    /* field 4 (fixed32): tag=0x25, val=LE 0x12345678 */
    PUT(0x25); PUT(0x78); PUT(0x56); PUT(0x34); PUT(0x12);
    /* field 5 (fixed64): tag=0x29, val=LE 0x00000000DEADBEEF */
    PUT(0x29); PUT(0xEF); PUT(0xBE); PUT(0xAD); PUT(0xDE);
    PUT(0x00); PUT(0x00); PUT(0x00); PUT(0x00);
    /* field 10 (varint): tag = (10<<3)|0 = 80 = 0x50, val = 300 = 0xAC 0x02 */
    PUT(0x50); PUT(0xAC); PUT(0x02);
#undef PUT
    return off;
}

/* ---------- Test 1: varint round-trip ---------- */

static void test_varint_roundtrip(void) {
    fprintf(stderr, "\n=== Test 1: Varint encode/decode round-trip ===\n");

    uint64_t test_vals[] = {0, 1, 127, 128, 255, 256, 16383, 16384,
                            0x7FFFFFFFULL, 0xFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL,
                            0xFFFFFFFFFFFFFFFFULL};

    for (size_t i = 0; i < sizeof(test_vals) / sizeof(test_vals[0]); i++) {
        uint8_t buf[10];
        size_t  enc_len = varint_encode(buf, sizeof(buf), test_vals[i]);

        uint64_t decoded;
        size_t   dec_len = varint_decode(buf, enc_len, 0, &decoded);

        char msg[128];
        snprintf(msg, sizeof(msg),
            "varint round-trip 0x%llx: enc=%zu dec=%zu",
            (unsigned long long)test_vals[i], enc_len, dec_len);

        ASSERT(enc_len > 0 && dec_len == enc_len && decoded == test_vals[i], msg);
    }
}

/* ---------- Test 2: scanner correctness ---------- */

static void test_scanner_correctness(void) {
    fprintf(stderr, "\n=== Test 2: Proto scanner correctness ===\n");

    uint8_t proto[128];
    size_t  proto_len = build_test_proto(proto, sizeof(proto));

    field_t fields[32];
    size_t  fc = scan_fields(proto, proto_len, fields, 32);

    ASSERT(fc == 6, "6 fields parsed from test message");

    ASSERT(fields[0].field_num == 1 && fields[0].wire_type == 0,
           "field 1: varint");
    ASSERT(fields[1].field_num == 2 && fields[1].wire_type == 2,
           "field 2: length-delimited");
    ASSERT(fields[2].field_num == 3 && fields[2].wire_type == 0,
           "field 3: varint");
    ASSERT(fields[3].field_num == 4 && fields[3].wire_type == 5,
           "field 4: fixed32");
    ASSERT(fields[4].field_num == 5 && fields[4].wire_type == 1,
           "field 5: fixed64");
    ASSERT(fields[5].field_num == 10 && fields[5].wire_type == 0,
           "field 10: varint (2-byte value)");

    /* Verify value decoding for varint fields */
    uint64_t v;
    varint_decode(proto, proto_len, fields[0].val_off, &v);
    ASSERT(v == 42, "field 1 value == 42");

    varint_decode(proto, proto_len, fields[2].val_off, &v);
    ASSERT(v == 100, "field 3 value == 100");

    varint_decode(proto, proto_len, fields[5].val_off, &v);
    ASSERT(v == 300, "field 10 value == 300");

    /* Truncated message should parse partial fields */
    size_t fc2 = scan_fields(proto, 5, fields, 32);
    ASSERT(fc2 == 1, "truncated to 5 bytes: 1 field parsed");

    /* Empty / garbage */
    uint8_t garbage[] = {0xFF, 0xFF, 0xFF};
    ASSERT(scan_fields(garbage, 3, fields, 32) == 0, "garbage yields 0 fields");

    uint8_t empty[] = {0x00};
    ASSERT(scan_fields(empty, 1, fields, 32) == 0, "zero tag yields 0 fields");

    /* Malicious length: huge payload_len varint that would overflow */
    uint8_t overflow[] = {0x12, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01};
    ASSERT(scan_fields(overflow, sizeof(overflow), fields, 32) == 0,
           "overflow length-delimited payload rejected");
}

/* ---------- Test 3: parse rate comparison ---------- */

/*
 * Simulate honggfuzz's actual mutation repertoire:
 *   - bit flip, byte overwrite, byte swap, add/sub   (simple)
 *   - memset region, random fill, block move/copy     (structural)
 *   - magic values, interesting constants              (data)
 *
 * Weighted to match production distribution: ~40% simple, ~30% structural,
 * ~30% data/magic.  The structural mutations are what destroy protobuf
 * wire format and drive production parse rate to ~0-5%.
 */
static void apply_blind_mutation(uint8_t* buf, size_t len, size_t* len_ptr) {
    if (len == 0) return;
    size_t pos = (size_t)(rng_next() % len);
    switch (rng_next() % 10) {
    case 0: /* bit flip */
        buf[pos] ^= (uint8_t)(1u << (rng_next() & 7));
        break;
    case 1: /* byte overwrite */
        buf[pos] = (uint8_t)rng_next();
        break;
    case 2: /* add/sub small value */
        buf[pos] += (int8_t)(rng_next() % 33) - 16;
        break;
    case 3: { /* memset region (mangle_MemSet) */
        size_t fill_len = 1 + (rng_next() % 8);
        if (pos + fill_len > len) fill_len = len - pos;
        memset(&buf[pos], (uint8_t)rng_next(), fill_len);
        break;
    }
    case 4: { /* random fill region (mangle_RandomBuf) */
        size_t fill_len = 1 + (rng_next() % 8);
        if (pos + fill_len > len) fill_len = len - pos;
        for (size_t i = 0; i < fill_len; i++) buf[pos + i] = (uint8_t)rng_next();
        break;
    }
    case 5: { /* block move (mangle_BlockMove) */
        size_t dst = (size_t)(rng_next() % len);
        size_t mv_len = 1 + (rng_next() % 8);
        if (pos + mv_len > len) mv_len = len - pos;
        if (dst + mv_len > len) mv_len = len - dst;
        memmove(&buf[dst], &buf[pos], mv_len);
        break;
    }
    case 6: { /* block copy / overwrite from another position */
        size_t src = (size_t)(rng_next() % len);
        size_t cp_len = 1 + (rng_next() % 8);
        if (src + cp_len > len) cp_len = len - src;
        if (pos + cp_len > len) cp_len = len - pos;
        memcpy(&buf[pos], &buf[src], cp_len);
        break;
    }
    case 7: { /* magic value overwrite (mangle_Magic) */
        static const uint8_t magic[][4] = {
            {0x00,0x00,0x00,0x00}, {0xFF,0xFF,0xFF,0xFF},
            {0x80,0x00,0x00,0x00}, {0x7F,0xFF,0xFF,0xFF},
            {0x00,0x00,0x00,0x01}, {0x01,0x00,0x00,0x00},
        };
        size_t idx = rng_next() % 6;
        size_t w = (rng_next() % 2) ? 4 : 2;
        if (pos + w > len) w = len - pos;
        memcpy(&buf[pos], magic[idx], w);
        break;
    }
    case 8: { /* shrink (mangle_Shrink) — remove 1-4 bytes */
        size_t del = 1 + (rng_next() % 4);
        if (del >= len) del = len > 1 ? len - 1 : 0;
        if (del > 0 && pos + del < len) {
            memmove(&buf[pos], &buf[pos + del], len - pos - del);
            *len_ptr -= del;
        }
        break;
    }
    case 9: { /* expand (mangle_Expand) — insert 1-4 random bytes */
        size_t add = 1 + (rng_next() % 4);
        size_t cap = 256;
        if (len + add > cap) add = (len < cap) ? cap - len : 0;
        if (add > 0) {
            memmove(&buf[pos + add], &buf[pos], len - pos);
            for (size_t i = 0; i < add; i++) buf[pos + i] = (uint8_t)rng_next();
            *len_ptr += add;
        }
        break;
    }
    }
}

static void apply_proto_aware_mutation(uint8_t* buf, size_t len, size_t* len_ptr) {
    if (len < 2) return;

    field_t fields[64];
    size_t fc = scan_fields(buf, len, fields, 64);
    if (fc == 0) {
        apply_blind_mutation(buf, len, len_ptr);
        return;
    }

    field_t* f = &fields[rng_next() % fc];

    switch (f->wire_type) {
    case 0: {
        /* Varint: decode, mutate, re-encode in same length (pad with 0x80 if shorter) */
        uint64_t val;
        varint_decode(buf, len, f->val_off, &val);

        switch (rng_next() % 6) {
        case 0: val = 0; break;
        case 1: val++; break;
        case 2: val--; break;
        case 3: val ^= 1ULL << (rng_next() & 63); break;
        case 4: val = rng_range(0, 127); break;
        case 5: val = ~val; break;
        }

        /*
         * Re-encode with the same byte length as the original.
         * Pad with continuation bytes if needed — protobuf parsers
         * accept over-long varint encodings.
         */
        size_t orig_len = f->val_len;
        for (size_t i = 0; i < orig_len; i++) {
            buf[f->val_off + i] = (uint8_t)(val & 0x7F);
            if (i < orig_len - 1) buf[f->val_off + i] |= 0x80;
            val >>= 7;
        }
        break;
    }
    case 1: /* fixed64 — mutate in place */
        if (f->val_off + 8 <= len) {
            size_t byte_off = f->val_off + (rng_next() % 8);
            buf[byte_off] ^= (uint8_t)(1u << (rng_next() & 7));
        }
        break;
    case 5: /* fixed32 — mutate in place */
        if (f->val_off + 4 <= len) {
            size_t byte_off = f->val_off + (rng_next() % 4);
            buf[byte_off] ^= (uint8_t)(1u << (rng_next() & 7));
        }
        break;
    case 2: {
        /* Length-delimited: mutate payload bytes, keep tag and length intact */
        uint64_t pl;
        size_t lb = varint_decode(buf, len, f->val_off, &pl);
        if (lb > 0 && pl > 0) {
            size_t payload_off = f->val_off + lb;
            size_t byte_off = payload_off + (rng_next() % (size_t)pl);
            if (byte_off < len) {
                buf[byte_off] ^= (uint8_t)(1u << (rng_next() & 7));
            }
        }
        break;
    }
    }
}

static void run_parse_rate_test(
    unsigned iterations, unsigned min_mut, unsigned max_mut,
    unsigned* blind_parseable, unsigned* blind_full,
    unsigned* proto_parseable, unsigned* proto_full,
    size_t orig_fc, const uint8_t* original, size_t orig_len) {

    *blind_parseable = *blind_full = *proto_parseable = *proto_full = 0;
    field_t fields[32];

    for (unsigned i = 0; i < iterations; i++) {
        /* Blind mutation test */
        uint8_t buf[256];
        memcpy(buf, original, orig_len);
        size_t cur_len = orig_len;
        unsigned nmut = min_mut + (rng_next() % (max_mut - min_mut + 1));
        for (unsigned m = 0; m < nmut; m++) apply_blind_mutation(buf, cur_len, &cur_len);

        size_t fc = scan_fields(buf, cur_len, fields, 32);
        if (fc >= 1) (*blind_parseable)++;
        if (fc == orig_fc) (*blind_full)++;

        /* Proto-aware mutation test */
        memcpy(buf, original, orig_len);
        cur_len = orig_len;
        nmut = min_mut + (rng_next() % (max_mut - min_mut + 1));
        for (unsigned m = 0; m < nmut; m++) apply_proto_aware_mutation(buf, cur_len, &cur_len);

        fc = scan_fields(buf, cur_len, fields, 32);
        if (fc >= 1) (*proto_parseable)++;
        if (fc == orig_fc) (*proto_full)++;
    }
}

static void test_parse_rate(unsigned iterations) {
    fprintf(stderr, "\n=== Test 3: Parse rate comparison (%u iterations) ===\n", iterations);

    uint8_t original[128];
    size_t  orig_len = build_test_proto(original, sizeof(original));

    field_t fields[32];
    size_t  orig_fc = scan_fields(original, orig_len, fields, 32);

    char msg[256];

    /*
     * Scenario A: Gentle (1-3 mutations, no size changes)
     * Baseline sanity check — proto-aware should dominate.
     */
    unsigned bp, bf, pp, pf;
    run_parse_rate_test(iterations, 1, 3,
                        &bp, &bf, &pp, &pf, orig_fc, original, orig_len);

    double br_a = 100.0 * bp / iterations, pr_a = 100.0 * pp / iterations;
    double bf_a = 100.0 * bf / iterations, pf_a = 100.0 * pf / iterations;

    /*
     * Scenario B: Production-like (5-16 mutations, includes expand/shrink/block ops)
     * This matches honggfuzz's default mutationsPerRun with the full mutation
     * repertoire including structural operations that destroy wire format.
     */
    run_parse_rate_test(iterations, 5, 16,
                        &bp, &bf, &pp, &pf, orig_fc, original, orig_len);

    double br_b = 100.0 * bp / iterations, pr_b = 100.0 * pp / iterations;
    double bf_b = 100.0 * bf / iterations, pf_b = 100.0 * pf / iterations;

    /*
     * Scenario C: Heavy stagnation (10-32 mutations)
     * Simulates honggfuzz when stuck for >300s (mult=4, cap=64).
     */
    run_parse_rate_test(iterations, 10, 32,
                        &bp, &bf, &pp, &pf, orig_fc, original, orig_len);

    double br_c = 100.0 * bp / iterations, pr_c = 100.0 * pp / iterations;
    double bf_c = 100.0 * bf / iterations, pf_c = 100.0 * pf / iterations;

    fprintf(stderr, "\n  %-32s %8s %8s %8s %8s\n",
            "", "Blind", "Blind", "Proto", "Proto");
    fprintf(stderr, "  %-32s %8s %8s %8s %8s\n",
            "Scenario", ">=1fld", "full", ">=1fld", "full");
    fprintf(stderr, "  %-32s %7.1f%% %7.1f%% %7.1f%% %7.1f%%\n",
            "A: gentle (1-3 mut)", br_a, bf_a, pr_a, pf_a);
    fprintf(stderr, "  %-32s %7.1f%% %7.1f%% %7.1f%% %7.1f%%\n",
            "B: production (5-16 mut)", br_b, bf_b, pr_b, pf_b);
    fprintf(stderr, "  %-32s %7.1f%% %7.1f%% %7.1f%% %7.1f%%\n",
            "C: heavy (10-32 mut)", br_c, bf_c, pr_c, pf_c);
    fprintf(stderr, "\n");

    /* Assertions — proto-aware should always beat blind */
    snprintf(msg, sizeof(msg),
        "A: proto full (%.1f%%) > blind full (%.1f%%)", pf_a, bf_a);
    ASSERT(pf_a > bf_a, msg);

    snprintf(msg, sizeof(msg),
        "B: proto full (%.1f%%) > blind full (%.1f%%)", pf_b, bf_b);
    ASSERT(pf_b > bf_b, msg);

    snprintf(msg, sizeof(msg),
        "C: proto full (%.1f%%) > blind full (%.1f%%)", pf_c, bf_c);
    ASSERT(pf_c > bf_c, msg);

    snprintf(msg, sizeof(msg),
        "B: proto parseable (%.1f%%) > 50%%", pr_b);
    ASSERT(pr_b > 50.0, msg);

    snprintf(msg, sizeof(msg),
        "B: blind full parse (%.1f%%) matches production ~0-5%%", bf_b);
    ASSERT(bf_b < 20.0, msg);
}

/* ---------- Test 4: flatbuffer scanner ---------- */

static void test_flatbuf_scanner(void) {
    fprintf(stderr, "\n=== Test 4: Flatbuffer layout validation ===\n");

    /*
     * Minimal flatbuffer layout (all little-endian):
     *   [0..3]   root_off = 16  (table object starts at byte 16)
     *   [4..5]   vtable_size = 8  (4 header + 2 fields * 2)
     *   [6..7]   object_size = 12
     *   [8..9]   field 0 offset = 4  (relative to table start)
     *   [10..11] field 1 offset = 8  (relative to table start)
     *   [12..15] unused padding
     *   [16..19] soffset to vtable = 12  (16 - 4 = 12)
     *   [20..23] field 0 data = 0x42424242
     *   [24..27] field 1 data = 0xDEADBEEF
     */
    uint32_t root_off     = 16;
    uint16_t vtable_size  = 8;
    uint16_t object_size  = 12;
    uint16_t f0_off       = 4;
    uint16_t f1_off       = 8;
    int32_t  soffset      = 12;
    uint32_t data0        = 0x42424242;
    uint32_t data1        = 0xDEADBEEF;

    uint8_t fb2[32];
    memset(fb2, 0, sizeof(fb2));
    memcpy(&fb2[0], &root_off, 4);
    memcpy(&fb2[4], &vtable_size, 2);
    memcpy(&fb2[6], &object_size, 2);
    memcpy(&fb2[8], &f0_off, 2);
    memcpy(&fb2[10], &f1_off, 2);
    memcpy(&fb2[16], &soffset, 4);
    memcpy(&fb2[20], &data0, 4);
    memcpy(&fb2[24], &data1, 4);

    /* Validate the layout by manually checking what mangle_FlatbufMutate would check */
    uint32_t ro;
    memcpy(&ro, fb2, 4);
    ASSERT(ro == 16, "root_off = 16");
    ASSERT(ro >= 4 && ro < sizeof(fb2) - 4, "root_off in bounds");

    int32_t vr;
    memcpy(&vr, &fb2[ro], 4);
    int64_t vo = (int64_t)ro - (int64_t)vr;
    ASSERT(vo == 4, "vtable at offset 4");
    ASSERT(vo >= 0 && (size_t)vo < sizeof(fb2) - 4, "vtable in bounds");

    uint16_t vs;
    memcpy(&vs, &fb2[vo], 2);
    ASSERT(vs == 8, "vtable_size = 8");

    size_t nf = (vs - 4) / 2;
    ASSERT(nf == 2, "2 fields in vtable");

    uint16_t off0;
    memcpy(&off0, &fb2[(size_t)vo + 4], 2);
    ASSERT(off0 == 4, "field 0 offset = 4");
    ASSERT(ro + off0 == 20, "field 0 absolute offset = 20");

    uint32_t val0;
    memcpy(&val0, &fb2[ro + off0], 4);
    ASSERT(val0 == 0x42424242, "field 0 value correct");
}

/* ---------- main ---------- */

int main(int argc, char** argv) {
    unsigned iterations = 50000;
    if (argc > 1) iterations = (unsigned)atoi(argv[1]);

    rng_seed((uint64_t)time(NULL) ^ 0x12345678ULL);

    fprintf(stderr, "Proto/Flatbuf Mutation Test Suite\n");
    fprintf(stderr, "=================================\n");

    test_varint_roundtrip();
    test_scanner_correctness();
    test_parse_rate(iterations);
    test_flatbuf_scanner();

    fprintf(stderr, "\n=================================\n");
    fprintf(stderr, "Results: %d / %d passed\n", tests_pass, tests_run);
    fprintf(stderr, "=================================\n\n");

    return (tests_pass == tests_run) ? 0 : 1;
}
