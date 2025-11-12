/** 
 * OpenCL kernel for Ethereum Brainwallet (m99999, -a 0).
 * (полный код ядра)
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_hash_sha256.cl"
#include "inc_ecc_secp256k1.cl"
#include "inc_hash_keccak.cl"
#include "inc_rp_optimized.cl"
#include "inc_rp.cl"
#include "inc_scalar.cl"

// UTF-16LE to UTF-8 decoder (per u16 char)
DECLSPEC void utf16le_to_utf8 (const u16 code, __local u8 *pw_bytes, u32 *pw_bytes_len)
{
  if (code < 0x80u)
  {
    pw_bytes[*pw_bytes_len] = (u8) code;
    (*pw_bytes_len)++;
  }
  else if (code < 0x800u)
  {
    pw_bytes[*pw_bytes_len + 0] = (u8) (0xC0u | (code >> 6u));
    pw_bytes[*pw_bytes_len + 1] = (u8) (0x80u | (code & 0x3Fu));
    (*pw_bytes_len) += 2;
  }
  else
  {
    if (code >= 0xD800u && code < 0xE000u) { return; }
    pw_bytes[*pw_bytes_len + 0] = (u8) (0xE0u | (code >> 12u));
    pw_bytes[*pw_bytes_len + 1] = (u8) (0x80u | ((code >> 6u) & 0x3Fu));
    pw_bytes[*pw_bytes_len + 2] = (u8) (0x80u | (code & 0x3Fu));
    (*pw_bytes_len) += 3;
  }
}

DECLSPEC void m99999_mxx (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 pw_buf0[4], pw_buf1[4];
  pw_buf0[0] = pws[gid].i[0]; pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2]; pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4]; pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6]; pw_buf1[3] = pws[gid].i[7];
  const u32 pw_len = pws[gid].pw_len & 63;

  u32x w0[4] = { 0 }, w1[4] = { 0 }, w2[4] = { 0 }, w3[4] = { 0 };
  make_utf16le (16, pw_len, pw_buf0, pw_buf1, w0, w1, w2, w3);
  const u32x out_len = apply_rules_vect (pw_len, w0, w1, w2, w3, rules_buf, RUL_CNT);

  __local u8 pw_bytes[256] = { 0 };
  u32 pw_bytes_len = 0;
  #pragma unroll
  for (u32 i = 0; i < out_len; i++)
  {
    const u32 word_idx = i / 2;
    const u32 shift = (i % 2u) * 16u;
    const u32x w_full = (i < 4 ? w0[i] : i < 8 ? w1[i-4] : i < 12 ? w2[i-8] : w3[i-12]);
    const u16 code = (u16) ((w_full >> shift) & 0xFFFFu);
    utf16le_to_utf8 (code, pw_bytes, &pw_bytes_len);
    if (pw_bytes_len >= 255u) break;
  }

  u32x w_sha[16] = { 0 };
  u32 pos = 0;
  #pragma unroll
  for (u32 j = 0; j < pw_bytes_len; j++)
  {
    const u32 word_idx = pos / 4u;
    const u32 byte_off = pos % 4u;
    w_sha[word_idx] |= ((u32x) pw_bytes[j]) << (8u * byte_off);
    pos++;
  }
  const u32 pad_word = pos / 4u;
  const u32 pad_off = pos % 4u;
  w_sha[pad_word] |= 0x80000000u >> (24u - 8u * pad_off);
  const u64 len_bits = ((u64) pw_bytes_len) * 8u;
  w_sha[14] = hc_swap32_S ((u32) (len_bits >> 32u));
  w_sha[15] = hc_swap32_S ((u32) len_bits);

  u32x priv[8] = { 0 };
  sha256_init (priv);
  sha256_transform (w_sha +  0, w_sha +  4, w_sha +  8, w_sha + 12, priv);

  u32x pub_x[8] = { 0 }, pub_y[8] = { 0 };
  secp256k1_mult_base (priv, pub_x, pub_y);

  u32 pub_bytes_le[16] = { 0 };
  #pragma unroll
  for (u32 i = 0; i < 8; i++)
  {
    pub_bytes_le[i + 0] = hc_swap32_S (pub_x[i]);
    pub_bytes_le[i + 8] = hc_swap32_S (pub_y[i]);
  }

  u32x keccak_out[8] = { 0 };
  keccak256_transform (pub_bytes_le, 64u, keccak_out);

  u32x addr0 = keccak_out[3];
  u32x addr1 = keccak_out[4];
  u32x addr2 = keccak_out[5];
  u32x addr3 = keccak_out[6];
  u32x addr4 = keccak_out[7];

  const u32x r0 = addr0, r1 = addr1, r2 = addr2, r3 = addr3, r4 = addr4;

  #define il_pos 0
  #include VECT_COMPARE_M