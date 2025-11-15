/**
 * Author......: Custom Ethereum brainwallet module
 * License.....: MIT
 */

#define SECP256K1_TMPS_TYPE PRIVATE_AS

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#ifndef KECCAK_ROUNDS
#define KECCAK_ROUNDS 24
#endif

#define Theta1(s) (st[0 + s] ^ st[5 + s] ^ st[10 + s] ^ st[15 + s] ^ st[20 + s])

#define Theta2(s)               \
{                               \
  st[ 0 + s] ^= t;              \
  st[ 5 + s] ^= t;              \
  st[10 + s] ^= t;              \
  st[15 + s] ^= t;              \
  st[20 + s] ^= t;              \
}

#define Rho_Pi(s)               \
{                               \
  const u64 bc = st[keccakf_piln[s]]; \
  st[keccakf_piln[s]] = hc_rotl64_S (t, keccakf_rotc[s]); \
  t = bc;                       \
}

#define Chi(s)                  \
{                               \
  const u64 bc0 = st[ 0 + s];   \
  const u64 bc1 = st[ 1 + s];   \
  const u64 bc2 = st[ 2 + s];   \
  const u64 bc3 = st[ 3 + s];   \
  const u64 bc4 = st[ 4 + s];   \
  st[ 0 + s] ^= (~bc1) & bc2;   \
  st[ 1 + s] ^= (~bc2) & bc3;   \
  st[ 2 + s] ^= (~bc3) & bc4;   \
  st[ 3 + s] ^= (~bc4) & bc0;   \
  st[ 4 + s] ^= (~bc0) & bc1;   \
}

CONSTANT_VK u64a keccakf_rndc[24] =
{
  0x0000000000000001ULL, 0x0000000000008082ULL,
  0x800000000000808aULL, 0x8000000080008000ULL,
  0x000000000000808bULL, 0x0000000080000001ULL,
  0x8000000080008081ULL, 0x8000000000008009ULL,
  0x000000000000008aULL, 0x0000000000000088ULL,
  0x0000000080008009ULL, 0x000000008000000aULL,
  0x000000008000808bULL, 0x800000000000008bULL,
  0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL,
  0x000000000000800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL,
  0x0000000080000001ULL, 0x8000000080008008ULL
};

CONSTANT_VK u8a keccakf_rotc[24] =
{
   1,  3,  6, 10, 15, 21, 28, 36,
  45, 55,  2, 14, 27, 41, 56,  8,
  25, 43, 62, 18, 39, 61, 20, 44
};

CONSTANT_VK u8a keccakf_piln[24] =
{
  10,  7, 11, 17, 18,  3,  5, 16,
   8, 21, 24,  4, 15, 23, 19, 13,
  12,  2, 20, 14, 22,  9,  6,  1
};

DECLSPEC void keccak_transform (PRIVATE_AS u64 *st)
{
  for (u32 round = 0; round < KECCAK_ROUNDS; round++)
  {
    u64 bc0 = Theta1 (0);
    u64 bc1 = Theta1 (1);
    u64 bc2 = Theta1 (2);
    u64 bc3 = Theta1 (3);
    u64 bc4 = Theta1 (4);

    u64 t = bc4 ^ hc_rotl64_S (bc1, 1);
    Theta2 (0);
    t = bc0 ^ hc_rotl64_S (bc2, 1);
    Theta2 (1);
    t = bc1 ^ hc_rotl64_S (bc3, 1);
    Theta2 (2);
    t = bc2 ^ hc_rotl64_S (bc4, 1);
    Theta2 (3);
    t = bc3 ^ hc_rotl64_S (bc0, 1);
    Theta2 (4);

    t = st[1];

    Rho_Pi (0);
    Rho_Pi (1);
    Rho_Pi (2);
    Rho_Pi (3);
    Rho_Pi (4);
    Rho_Pi (5);
    Rho_Pi (6);
    Rho_Pi (7);
    Rho_Pi (8);
    Rho_Pi (9);
    Rho_Pi (10);
    Rho_Pi (11);
    Rho_Pi (12);
    Rho_Pi (13);
    Rho_Pi (14);
    Rho_Pi (15);
    Rho_Pi (16);
    Rho_Pi (17);
    Rho_Pi (18);
    Rho_Pi (19);
    Rho_Pi (20);
    Rho_Pi (21);
    Rho_Pi (22);
    Rho_Pi (23);

    Chi (0);
    Chi (5);
    Chi (10);
    Chi (15);
    Chi (20);

    st[0] ^= keccakf_rndc[round];
  }
}

DECLSPEC void keccak256 (PRIVATE_AS u8 *out, PRIVATE_AS const u8 *in, const u32 in_len)
{
  PRIVATE_AS u64 st[25];

  for (u32 i = 0; i < 25; i++) st[i] = 0;

  for (u32 i = 0; i < in_len; i++)
  {
    const u32 lane = i / 8;
    const u32 shift = (i % 8) * 8;

    st[lane] ^= ((u64) in[i]) << shift;
  }

  const u32 pad_lane = in_len / 8;
  const u32 pad_shift = (in_len % 8) * 8;

  st[pad_lane] ^= ((u64) 0x01) << pad_shift;
  st[(136 - 1) / 8] ^= ((u64) 0x80) << (((136 - 1) % 8) * 8);

  keccak_transform (st);

  for (u32 i = 0; i < 32; i++)
  {
    const u32 lane = i / 8;
    const u32 shift = (i % 8) * 8;

    out[i] = (u8) ((st[lane] >> shift) & 0xff);
  }
}

KERNEL_FQ KERNEL_FA void m99999_mxx (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  secp256k1_t preG;
  set_precomputed_basepoint_g (&preG);

  COPY_PW (pws[gid]);

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t pw = PASTE_PW;

    pw.pw_len = apply_rules (rules_buf[il_pos].cmds, pw.i, pw.pw_len);

    sha256_ctx_t ctx;

    sha256_init (&ctx);
    sha256_update_swap (&ctx, pw.i, pw.pw_len);
    sha256_final (&ctx);

    u32 priv[8];

    for (u32 i = 0; i < 8; i++)
    {
      priv[i] = hc_swap32_S (ctx.h[7 - i]);
    }

    u32 x[8];
    u32 y[8];

    point_mul_xy (x, y, priv, &preG);

    u8 pub_bytes[64];

    for (u32 w = 0; w < 8; w++)
    {
      const u32 word_x = x[7 - w];
      const u32 word_y = y[7 - w];

      const u32 off_x = w * 4;
      const u32 off_y = 32 + w * 4;

      pub_bytes[off_x + 0] = (u8) (word_x >> 24);
      pub_bytes[off_x + 1] = (u8) (word_x >> 16);
      pub_bytes[off_x + 2] = (u8) (word_x >>  8);
      pub_bytes[off_x + 3] = (u8) (word_x >>  0);

      pub_bytes[off_y + 0] = (u8) (word_y >> 24);
      pub_bytes[off_y + 1] = (u8) (word_y >> 16);
      pub_bytes[off_y + 2] = (u8) (word_y >>  8);
      pub_bytes[off_y + 3] = (u8) (word_y >>  0);
    }

    u8 keccak_out[32];

    keccak256 (keccak_out, pub_bytes, 64);

    u8 addr_bytes[20];

    for (u32 i = 0; i < 20; i++)
    {
      addr_bytes[i] = keccak_out[12 + i];
    }

    u32 addr[5];

    for (u32 i = 0; i < 5; i++)
    {
      const u32 base = i * 4;

      addr[i] = ((u32) addr_bytes[base + 0])
              | ((u32) addr_bytes[base + 1] <<  8)
              | ((u32) addr_bytes[base + 2] << 16)
              | ((u32) addr_bytes[base + 3] << 24);
    }

    const u32 r0 = addr[0];
    const u32 r1 = addr[1];
    const u32 r2 = addr[2];
    const u32 r3 = addr[3];

    #include COMPARE_M
  }
}
