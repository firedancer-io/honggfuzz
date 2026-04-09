#include "fd_base58.h"

// Ported from
// https://github.com/firedancer-io/firedancer/blob/main/src/ballet/base58/fd_base58.c
// https://github.com/firedancer-io/firedancer/blob/main/src/ballet/base58/fd_base58_tmpl.c

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>

/* base58_chars maps [0, 58) to the base58 character. */

static char const base58_chars[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#define BASE58_INVALID_CHAR (255)
#define BASE58_INVERSE_TABLE_OFFSET ('1')
#define BASE58_INVERSE_TABLE_SENTINEL                                          \
  ((1UL + (uint8_t)('z') - BASE58_INVERSE_TABLE_OFFSET))

/* base58_inverse maps (character value - '1') to [0, 58).  Invalid
   base58 characters map to BASE58_INVALID_CHAR.  The character after
   what 'z' would map to also maps to BASE58_INVALID_CHAR to facilitate
   branchless lookups.  Don't make it static so that it can be used from
   tests. */

#define BAD BASE58_INVALID_CHAR

uint8_t const base58_inverse[] = {
    0,   1,   2,   3,  4,  5,  6,  7,  8,  BAD, BAD, BAD, BAD, BAD, BAD,
    BAD, 9,   10,  11, 12, 13, 14, 15, 16, BAD, 17,  18,  19,  20,  21,
    BAD, 22,  23,  24, 25, 26, 27, 28, 29, 30,  31,  32,  BAD, BAD, BAD,
    BAD, BAD, BAD, 33, 34, 35, 36, 37, 38, 39,  40,  41,  42,  43,  BAD,
    44,  45,  46,  47, 48, 49, 50, 51, 52, 53,  54,  55,  56,  57,  BAD};

#undef BAD

template <uint64_t BYTE_CNT, uint64_t INTERMEDIATE_SZ, uint64_t ENCODED_LEN,
          auto enc_table, auto dec_table>
class Base58Encoder {
private:
  static constexpr uint64_t RAW58_SZ = INTERMEDIATE_SZ * 5UL;
  static constexpr uint64_t BINARY_SZ = (BYTE_CNT / 4UL);
  static constexpr uint64_t INTERMEDIATE_SZ_W_PADDING = INTERMEDIATE_SZ;

public:
  static void encode(std::string &out,
                     std::array<uint8_t, BYTE_CNT> const &bytes) noexcept {
    out.resize(ENCODED_LEN, '\0');

    /* Count leading zeros (needed for final output) */

    uint64_t in_leading_0s = 0UL;
    for (; in_leading_0s < BYTE_CNT; in_leading_0s++)
      if (bytes[in_leading_0s])
        break;

    /* X = sum_i bytes[i] * 2^(8*(BYTE_CNT-1-i)) */

    /* Convert N to 32-bit limbs:
       X = sum_i binary[i] * 2^(32*(BINARY_SZ-1-i)) */
    uint32_t binary[BINARY_SZ];
    for (uint64_t i = 0UL; i < BINARY_SZ; i++) {
      uint32_t x;
      std::memcpy(&x, &bytes[i * sizeof(uint32_t)], sizeof(uint32_t));
      binary[i] = __builtin_bswap32(x);
    }

    uint64_t R1div = 656356768UL; /* = 58^5 */

    /* Convert to the intermediate format:
         X = sum_i intermediate[i] * 58^(5*(INTERMEDIATE_SZ-1-i))
       Initially, we don't require intermediate[i] < 58^5, but we do want
       to make sure the sums don't overflow. */

    uint64_t intermediate[INTERMEDIATE_SZ_W_PADDING];

    std::memset(intermediate, 0, INTERMEDIATE_SZ_W_PADDING * sizeof(uint64_t));

    if (BYTE_CNT == 32) {

      /* The worst case is if binary[7] is (2^32)-1. In that case
         intermediate[8] will be be just over 2^63, which is fine. */

      for (uint64_t i = 0UL; i < BINARY_SZ; i++)
        for (uint64_t j = 0UL; j < INTERMEDIATE_SZ - 1UL; j++)
          intermediate[j + 1UL] +=
              (uint64_t)binary[i] * (uint64_t)enc_table[i][j];

    } else if (BYTE_CNT == 64) {

      /* If we do it the same way as the 32B conversion, intermediate[16]
         can overflow when the input is sufficiently large.  We'll do a
         mini-reduction after the first 8 steps.  After the first 8 terms,
         the largest intermediate[16] can be is 2^63.87.  Then, after
         reduction it'll be at most 58^5, and after adding the last terms,
         it won't exceed 2^63.1.  We do need to be cautious that the
         mini-reduction doesn't cause overflow in intermediate[15] though.
         Pre-mini-reduction, it's at most 2^63.05.  The mini-reduction adds
         at most 2^64/58^5, which is negligible.  With the final terms, it
         won't exceed 2^63.69, which is fine. Other terms are less than
         2^63.76, so no problems there. */

      for (uint64_t i = 0UL; i < 8UL; i++)
        for (uint64_t j = 0UL; j < INTERMEDIATE_SZ - 1UL; j++)
          intermediate[j + 1UL] +=
              (uint64_t)binary[i] * (uint64_t)enc_table[i][j];
      /* Mini-reduction */
      intermediate[15] += intermediate[16] / R1div;
      intermediate[16] %= R1div;
      /* Finish iterations */
      for (uint64_t i = 8UL; i < BINARY_SZ; i++)
        for (uint64_t j = 0UL; j < INTERMEDIATE_SZ - 1UL; j++)
          intermediate[j + 1UL] +=
              (uint64_t)binary[i] * (uint64_t)enc_table[i][j];

    } else {
      __builtin_unreachable();
    }

    /* Now we make sure each term is less than 58^5. Again, we have to be
       a bit careful of overflow.

       For N==32, in the worst case, as before, intermediate[8] will be
       just over 2^63 and intermediate[7] will be just over 2^62.6.  In
       the first step, we'll add floor(intermediate[8]/58^5) to
       intermediate[7].  58^5 is pretty big though, so intermediate[7]
       barely budges, and this is still fine.

       For N==64, in the worst case, the biggest entry in intermediate at
       this point is 2^63.87, and in the worst case, we add (2^64-1)/58^5,
       which is still about 2^63.87. */

    for (uint64_t i = INTERMEDIATE_SZ - 1UL; i > 0UL; i--) {
      intermediate[i - 1UL] += (intermediate[i] / R1div);
      intermediate[i] %= R1div;
    }

    /* Convert intermediate form to base 58.  This form of conversion
       exposes tons of ILP, but it's more than the CPU can take advantage
       of.
         X = sum_i raw_base58[i] * 58^(RAW58_SZ-1-i) */

    uint8_t raw_base58[RAW58_SZ];
    for (uint64_t i = 0UL; i < INTERMEDIATE_SZ; i++) {
      /* We know intermediate[ i ] < 58^5 < 2^32 for all i, so casting to
         a uint is safe.  GCC doesn't seem to be able to realize this, so
         when it converts uint64_t/uint64_t to a magic multiplication, it
         generates the single-op 64b x 64b -> 128b mul instruction.  This
         hurts the CPU's ability to take advantage of the ILP here. */
      uint32_t v = (uint32_t)intermediate[i];
      raw_base58[5UL * i + 4UL] = (uint8_t)((v / 1U) % 58U);
      raw_base58[5UL * i + 3UL] = (uint8_t)((v / 58U) % 58U);
      raw_base58[5UL * i + 2UL] = (uint8_t)((v / 3364U) % 58U);
      raw_base58[5UL * i + 1UL] = (uint8_t)((v / 195112U) % 58U);
      raw_base58[5UL * i + 0UL] =
          (uint8_t)(v / 11316496U); /* We know this one is less than 58 */
    }

    /* Finally, actually convert to the string.  We have to ignore all the
       leading zeros in raw_base58 and instead insert in_leading_0s
       leading '1' characters.  We can show that raw_base58 actually has
       at least in_leading_0s, so we'll do this by skipping the first few
       leading zeros in raw_base58. */

    uint64_t raw_leading_0s = 0UL;
    for (; raw_leading_0s < RAW58_SZ; raw_leading_0s++)
      if (raw_base58[raw_leading_0s])
        break;

    /* It's not immediately obvious that raw_leading_0s >= in_leading_0s,
       but it's true.  In base b, X has floor(log_b X)+1 digits.  That
       means in_leading_0s = N-1-floor(log_256 X) and raw_leading_0s =
       RAW58_SZ-1-floor(log_58 X).  Let X<256^N be given and consider:

       raw_leading_0s - in_leading_0s =
         =  RAW58_SZ-N + floor( log_256 X ) - floor( log_58 X )
         >= RAW58_SZ-N - 1 + ( log_256 X - log_58 X ) .

       log_256 X - log_58 X is monotonically decreasing for X>0, so it
       achieves it minimum at the maximum possible value for X, i.e.
       256^N-1.
         >= RAW58_SZ-N-1 + log_256(256^N-1) - log_58(256^N-1)

       When N==32, RAW58_SZ is 45, so this gives skip >= 0.29
       When N==64, RAW58_SZ is 90, so this gives skip >= 1.59.

       Regardless, raw_leading_0s - in_leading_0s >= 0. */

    uint64_t skip = raw_leading_0s - in_leading_0s;
    for (uint64_t i = 0UL; i < RAW58_SZ - skip; i++)
      out[i] = base58_chars[raw_base58[skip + i]];

    out.resize(RAW58_SZ - skip);
  }

  static bool decode(std::array<uint8_t, BYTE_CNT> &out,
                     std::string const &encoded) noexcept {

    if (encoded.size() > ENCODED_LEN)
      return false; /* too long */

    uint64_t char_cnt = 0UL;
    for (; char_cnt < encoded.size(); char_cnt++) {
      char c = encoded[char_cnt];
      if (!c)
        break;
      /* If c<'1', this will underflow and idx will be huge */
      uint64_t idx =
          (uint64_t)(uint8_t)c - (uint64_t)BASE58_INVERSE_TABLE_OFFSET;
      idx = std::min(idx, BASE58_INVERSE_TABLE_SENTINEL);
      if (base58_inverse[idx] == BASE58_INVALID_CHAR)
        return false;
    }

    /* X = sum_i raw_base58[i] * 58^(RAW58_SZ-1-i) */

    uint8_t raw_base58[RAW58_SZ];

    /* Prepend enough 0s to make it exactly RAW58_SZ characters */

    uint64_t prepend_0 = RAW58_SZ - char_cnt;
    for (uint64_t j = 0UL; j < RAW58_SZ; j++)
      raw_base58[j] = (j < prepend_0)
                          ? (uint8_t)0
                          : base58_inverse[encoded[j - prepend_0] -
                                           BASE58_INVERSE_TABLE_OFFSET];

    /* Convert to the intermediate format (base 58^5):
         X = sum_i intermediate[i] * 58^(5*(INTERMEDIATE_SZ-1-i)) */

    uint64_t intermediate[INTERMEDIATE_SZ];
    for (uint64_t i = 0UL; i < INTERMEDIATE_SZ; i++)
      intermediate[i] = (uint64_t)raw_base58[5UL * i + 0UL] * 11316496UL +
                        (uint64_t)raw_base58[5UL * i + 1UL] * 195112UL +
                        (uint64_t)raw_base58[5UL * i + 2UL] * 3364UL +
                        (uint64_t)raw_base58[5UL * i + 3UL] * 58UL +
                        (uint64_t)raw_base58[5UL * i + 4UL] * 1UL;

    /* Using the table, convert to overcomplete base 2^32 (terms can be
       larger than 2^32).  We need to be careful about overflow.

       For N==32, the largest anything in binary can get is binary[7]:
       even if intermediate[i]==58^5-1 for all i, then binary[7] < 2^63.

       For N==64, the largest anything in binary can get is binary[13]:
       even if intermediate[i]==58^5-1 for all i, then binary[13] <
       2^63.998.  Hanging in there, just by a thread! */

    uint64_t binary[BINARY_SZ];
    for (uint64_t j = 0UL; j < BINARY_SZ; j++) {
      uint64_t acc = 0UL;
      for (uint64_t i = 0UL; i < INTERMEDIATE_SZ; i++)
        acc += (uint64_t)intermediate[i] * (uint64_t)dec_table[i][j];
      binary[j] = acc;
    }

    /* Make sure each term is less than 2^32.

       For N==32, we have plenty of headroom in binary, so overflow is
       not a concern this time.

       For N==64, even if we add 2^32 to binary[13], it is still 2^63.998,
       so this won't overflow. */

    for (ulong i = BINARY_SZ - 1UL; i > 0UL; i--) {
      binary[i - 1UL] += (binary[i] >> 32);
      binary[i] &= 0xFFFFFFFFUL;
    }

    /* If the largest term is 2^32 or bigger, it means N is larger than
       what can fit in BYTE_CNT bytes.  This can be triggered, by passing
       a base58 string of all 'z's for example. */

    if (binary[0UL] > 0xFFFFFFFFUL)
      return false;

    /* Convert each term to big endian for the final output */

    uint32_t *out_as_uint = reinterpret_cast<uint32_t *>(out.data());
    for (ulong i = 0UL; i < BINARY_SZ; i++) {
      uint32_t val = __builtin_bswap32((uint32_t)binary[i]);
      memcpy(&out_as_uint[i], &val, sizeof(uint32_t));
    }
    /* Make sure the encoded version has the same number of leading '1's
       as the decoded version has leading 0s. The check doesn't read past
       the end of encoded, because '\0' != '1', so it will return false. */

    uint64_t leading_zero_cnt = 0UL;
    for (; leading_zero_cnt < BYTE_CNT; leading_zero_cnt++) {
      if (out[leading_zero_cnt])
        break;
      if (encoded[leading_zero_cnt] != '1')
        return false;
    }
    if (encoded[leading_zero_cnt] == '1')
      return false;
    return true;
  }
};

/* Contains the unique values less than 58^5 such that:
     2^(32*(7-j)) = sum_k table[j][k]*58^(5*(7-k))

   The second dimension of this table is actually ceil(log_(58^5)
   (2^(32*(BINARY_SZ-1))), but that's almost always INTERMEDIATE_SZ-1 */

static uint32_t const enc_table_32[8][8] = {
    {513735U, 77223048U, 437087610U, 300156666U, 605448490U, 214625350U,
     141436834U, 379377856U},
    {0U, 78508U, 646269101U, 118408823U, 91512303U, 209184527U, 413102373U,
     153715680U},
    {0U, 0U, 11997U, 486083817U, 3737691U, 294005210U, 247894721U, 289024608U},
    {0U, 0U, 0U, 1833U, 324463681U, 385795061U, 551597588U, 21339008U},
    {0U, 0U, 0U, 0U, 280U, 127692781U, 389432875U, 357132832U},
    {0U, 0U, 0U, 0U, 0U, 42U, 537767569U, 410450016U},
    {0U, 0U, 0U, 0U, 0U, 0U, 6U, 356826688U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U}};

/* Contains the unique values less than 2^32 such that:
     58^(5*(8-j)) = sum_k table[j][k]*2^(32*(7-k)) */

static uint32_t const dec_table_32[9][8] = {
    {1277U, 2650397687U, 3801011509U, 2074386530U, 3248244966U, 687255411U,
     2959155456U, 0U},
    {0U, 8360U, 1184754854U, 3047609191U, 3418394749U, 132556120U, 1199103528U,
     0U},
    {0U, 0U, 54706U, 2996985344U, 1834629191U, 3964963911U, 485140318U,
     1073741824U},
    {0U, 0U, 0U, 357981U, 1476998812U, 3337178590U, 1483338760U, 4194304000U},
    {0U, 0U, 0U, 0U, 2342503U, 3052466824U, 2595180627U, 17825792U},
    {0U, 0U, 0U, 0U, 0U, 15328518U, 1933902296U, 4063920128U},
    {0U, 0U, 0U, 0U, 0U, 0U, 100304420U, 3355157504U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 656356768U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U}};

void fd_base58_encode_32(std::string &out,
                         std::array<uint8_t, 32> const &in) noexcept {
  Base58Encoder<32UL, 9UL, FD_BASE58_ENCODED_32_LEN, enc_table_32,
                dec_table_32>::encode(out, in);
}

bool fd_base58_decode_32(std::array<uint8_t, 32> &out,
                         std::string const &in) noexcept {
  return Base58Encoder<32UL, 9UL, FD_BASE58_ENCODED_32_LEN, enc_table_32,
                       dec_table_32>::decode(out, in);
}

/* Contains the unique values less than 58^5 such that
   2^(32*(15-j)) = sum_k table[j][k]*58^(5*(16-k)) */

static uint32_t const enc_table_64[16][17] = {
    {2631U, 149457141U, 577092685U, 632289089U, 81912456U, 221591423U,
     502967496U, 403284731U, 377738089U, 492128779U, 746799U, 366351977U,
     190199623U, 38066284U, 526403762U, 650603058U, 454901440U},
    {0U, 402U, 68350375U, 30641941U, 266024478U, 208884256U, 571208415U,
     337765723U, 215140626U, 129419325U, 480359048U, 398051646U, 635841659U,
     214020719U, 136986618U, 626219915U, 49699360U},
    {0U, 0U, 61U, 295059608U, 141201404U, 517024870U, 239296485U, 527697587U,
     212906911U, 453637228U, 467589845U, 144614682U, 45134568U, 184514320U,
     644355351U, 104784612U, 308625792U},
    {0U, 0U, 0U, 9U, 256449755U, 500124311U, 479690581U, 372802935U, 413254725U,
     487877412U, 520263169U, 176791855U, 78190744U, 291820402U, 74998585U,
     496097732U, 59100544U},
    {0U, 0U, 0U, 0U, 1U, 285573662U, 455976778U, 379818553U, 100001224U,
     448949512U, 109507367U, 117185012U, 347328982U, 522665809U, 36908802U,
     577276849U, 64504928U},
    {0U, 0U, 0U, 0U, 0U, 0U, 143945778U, 651677945U, 281429047U, 535878743U,
     264290972U, 526964023U, 199595821U, 597442702U, 499113091U, 424550935U,
     458949280U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 21997789U, 294590275U, 148640294U, 595017589U,
     210481832U, 404203788U, 574729546U, 160126051U, 430102516U, 44963712U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 3361701U, 325788598U, 30977630U,
     513969330U, 194569730U, 164019635U, 136596846U, 626087230U, 503769920U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 513735U, 77223048U, 437087610U,
     300156666U, 605448490U, 214625350U, 141436834U, 379377856U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 78508U, 646269101U, 118408823U,
     91512303U, 209184527U, 413102373U, 153715680U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 11997U, 486083817U, 3737691U,
     294005210U, 247894721U, 289024608U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1833U, 324463681U,
     385795061U, 551597588U, 21339008U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 280U, 127692781U,
     389432875U, 357132832U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 42U, 537767569U,
     410450016U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 6U,
     356826688U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U}};

static uint32_t const dec_table_64[18][16] = {
    {249448U, 3719864065U, 173911550U, 4021557284U, 3115810883U, 2498525019U,
     1035889824U, 627529458U, 3840888383U, 3728167192U, 2901437456U,
     3863405776U, 1540739182U, 1570766848U, 0U, 0U},
    {0U, 1632305U, 1882780341U, 4128706713U, 1023671068U, 2618421812U,
     2005415586U, 1062993857U, 3577221846U, 3960476767U, 1695615427U,
     2597060712U, 669472826U, 104923136U, 0U, 0U},
    {0U, 0U, 10681231U, 1422956801U, 2406345166U, 4058671871U, 2143913881U,
     4169135587U, 2414104418U, 2549553452U, 997594232U, 713340517U, 2290070198U,
     1103833088U, 0U, 0U},
    {0U, 0U, 0U, 69894212U, 1038812943U, 1785020643U, 1285619000U, 2301468615U,
     3492037905U, 314610629U, 2761740102U, 3410618104U, 1699516363U, 910779968U,
     0U, 0U},
    {0U, 0U, 0U, 0U, 457363084U, 927569770U, 3976106370U, 1389513021U,
     2107865525U, 3716679421U, 1828091393U, 2088408376U, 439156799U,
     2579227194U, 0U, 0U},
    {0U, 0U, 0U, 0U, 0U, 2992822783U, 383623235U, 3862831115U, 112778334U,
     339767049U, 1447250220U, 486575164U, 3495303162U, 2209946163U, 268435456U,
     0U},
    {0U, 0U, 0U, 0U, 0U, 4U, 2404108010U, 2962826229U, 3998086794U, 1893006839U,
     2266258239U, 1429430446U, 307953032U, 2361423716U, 176160768U, 0U},
    {0U, 0U, 0U, 0U, 0U, 0U, 29U, 3596590989U, 3044036677U, 1332209423U,
     1014420882U, 868688145U, 4264082837U, 3688771808U, 2485387264U, 0U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 195U, 1054003707U, 3711696540U, 582574436U,
     3549229270U, 1088536814U, 2338440092U, 1468637184U, 0U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1277U, 2650397687U, 3801011509U,
     2074386530U, 3248244966U, 687255411U, 2959155456U, 0U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 8360U, 1184754854U, 3047609191U,
     3418394749U, 132556120U, 1199103528U, 0U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 54706U, 2996985344U, 1834629191U,
     3964963911U, 485140318U, 1073741824U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 357981U, 1476998812U,
     3337178590U, 1483338760U, 4194304000U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 2342503U, 3052466824U,
     2595180627U, 17825792U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 15328518U, 1933902296U,
     4063920128U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 100304420U,
     3355157504U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 656356768U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U}};

void fd_base58_encode_64(std::string &out,
                         std::array<uint8_t, 64> const &in) noexcept {
  Base58Encoder<64UL, 18UL, FD_BASE58_ENCODED_64_LEN, enc_table_64,
                dec_table_64>::encode(out, in);
}

bool fd_base58_decode_64(std::array<uint8_t, 64> &out,
                         std::string const &in) noexcept {
  return Base58Encoder<64UL, 18UL, FD_BASE58_ENCODED_64_LEN, enc_table_64,
                       dec_table_64>::decode(out, in);
}
