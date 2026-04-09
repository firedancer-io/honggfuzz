#ifndef HEADER_fd_src_ballet_base58_fd_base58_h
#define HEADER_fd_src_ballet_base58_fd_base58_h

// Ported from
// https://github.com/firedancer-io/firedancer/blob/main/src/ballet/base58/fd_base58.h

#include <array>
#include <cstdint>
#include <optional>
#include <string>

/* FD_BASE58_ENCODED_{32,64}_{LEN,SZ} give the maximum string length
   (LEN) and size (SZ, which includes the '\0') of the base58 cstrs that
   result from converting 32 or 64 bytes to base58. */

#define FD_BASE58_ENCODED_32_LEN                                               \
  (44UL) /* Computed as ceil(log_58(256^32 - 1)) */
#define FD_BASE58_ENCODED_64_LEN                                               \
  (88UL) /* Computed as ceil(log_58(256^64 - 1)) */

void fd_base58_encode_32(std::string &out,
                         std::array<uint8_t, 32> const &in) noexcept;
void fd_base58_encode_64(std::string &out,
                         std::array<uint8_t, 64> const &in) noexcept;

static inline std::string
fd_base58_encode_32_str(std::array<uint8_t, 32> const &addr) noexcept {
  std::string result(FD_BASE58_ENCODED_32_LEN, '\0');
  fd_base58_encode_32(result, addr);
  return result;
}

static inline std::string
fd_base58_encode_64_str(std::array<uint8_t, 64> const &addr) noexcept {
  std::string result(FD_BASE58_ENCODED_64_LEN, '\0');
  fd_base58_encode_64(result, addr);
  return result;
}

bool fd_base58_decode_32(std::array<uint8_t, 32> &out,
                         std::string const &in) noexcept;
bool fd_base58_decode_64(std::array<uint8_t, 64> &out,
                         std::string const &in) noexcept;

static inline std::optional<std::array<uint8_t, 32>>
fd_base58_decode_32_opt(std::string const &in) noexcept {
  std::array<uint8_t, 32> result;
  if (fd_base58_decode_32(result, in)) {
    return result;
  }
  return std::nullopt;
}

static inline std::optional<std::array<uint8_t, 64>>
fd_base58_decode_64_opt(std::string const &in) noexcept {
  std::array<uint8_t, 64> result;
  if (fd_base58_decode_64(result, in)) {
    return result;
  }
  return std::nullopt;
}

#endif /* HEADER_fd_src_ballet_base58_fd_base58_h */
