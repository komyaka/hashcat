/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#define SECP256K1_TMPS_TYPE PRIVATE_AS

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_keccak.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#endif

KERNEL_FQ void m35910_mxx (KERN_ATTR_VECTOR ())
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  secp256k1_t preG;
  set_precomputed_basepoint_g (&preG);

  u32 w[16];
  w[0]  = pws[gid].i[0];
  w[1]  = pws[gid].i[1];
  w[2]  = pws[gid].i[2];
  w[3]  = pws[gid].i[3];
  w[4]  = pws[gid].i[4];
  w[5]  = pws[gid].i[5];
  w[6]  = pws[gid].i[6];
  w[7]  = pws[gid].i[7];
  w[8]  = 0;
  w[9]  = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len;

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 w_final[16];
    w_final[0]  = w[0];
    w_final[1]  = w[1];
    w_final[2]  = w[2];
    w_final[3]  = w[3];
    w_final[4]  = w[4];
    w_final[5]  = w[5];
    w_final[6]  = w[6];
    w_final[7]  = w[7];
    w_final[8]  = 0;
    w_final[9]  = 0;
    w_final[10] = 0;
    w_final[11] = 0;
    w_final[12] = 0;
    w_final[13] = 0;
    w_final[14] = 0;
    w_final[15] = 0;

    const u32 pw_len_final = apply_rules_vect (rules_buf, il_pos, w_final, pw_len);

    sha256_ctx_t sha_ctx;
    sha256_init (&sha_ctx);
    sha256_update_swap (&sha_ctx, w_final, pw_len_final);
    sha256_final (&sha_ctx);

    u32 prv_key[9];
    prv_key[0] = sha_ctx.h[7];
    prv_key[1] = sha_ctx.h[6];
    prv_key[2] = sha_ctx.h[5];
    prv_key[3] = sha_ctx.h[4];
    prv_key[4] = sha_ctx.h[3];
    prv_key[5] = sha_ctx.h[2];
    prv_key[6] = sha_ctx.h[1];
    prv_key[7] = sha_ctx.h[0];
    prv_key[8] = 0;

    u32 x[8], y[8];
    point_mul_xy (x, y, prv_key, &preG);

    u32 pub_key[16];
    pub_key[0]  = hc_swap32_S (x[7]);
    pub_key[1]  = hc_swap32_S (x[6]);
    pub_key[2]  = hc_swap32_S (x[5]);
    pub_key[3]  = hc_swap32_S (x[4]);
    pub_key[4]  = hc_swap32_S (x[3]);
    pub_key[5]  = hc_swap32_S (x[2]);
    pub_key[6]  = hc_swap32_S (x[1]);
    pub_key[7]  = hc_swap32_S (x[0]);
    pub_key[8]  = hc_swap32_S (y[7]);
    pub_key[9]  = hc_swap32_S (y[6]);
    pub_key[10] = hc_swap32_S (y[5]);
    pub_key[11] = hc_swap32_S (y[4]);
    pub_key[12] = hc_swap32_S (y[3]);
    pub_key[13] = hc_swap32_S (y[2]);
    pub_key[14] = hc_swap32_S (y[1]);
    pub_key[15] = hc_swap32_S (y[0]);

    u32 keccak_st[25] = { 0 };
    for (u32 i = 0; i < 16; i++) keccak_st[i] = hc_swap32_S (pub_key[i]);

    u64 st64[25] = { 0 };
    for (u32 i = 0; i < 8; i++)
      st64[i] = hl32_to_64_S (keccak_st[i * 2 + 1], keccak_st[i * 2 + 0]);

    keccak_transform_S (st64, 64, 200, 0x01, 256);

    u32 hash32[8];
    hash32[0] = l32_from_64_S (st64[0]);
    hash32[1] = h32_from_64_S (st64[0]);
    hash32[2] = l32_from_64_S (st64[1]);
    hash32[3] = h32_from_64_S (st64[1]);
    hash32[4] = l32_from_64_S (st64[2]);
    hash32[5] = h32_from_64_S (st64[2]);
    hash32[6] = l32_from_64_S (st64[3]);
    hash32[7] = h32_from_64_S (st64[3]);

    const u32 r0 = hash32[3];
    const u32 r1 = hash32[4];
    const u32 r2 = hash32[5];
    const u32 r3 = hash32[6];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m35910_sxx (KERN_ATTR_VECTOR ())
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  secp256k1_t preG;
  set_precomputed_basepoint_g (&preG);

  u32 s[4];
  s[0] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0];
  s[1] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1];
  s[2] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2];
  s[3] = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3];

  u32 w[16];
  w[0]  = pws[gid].i[0];
  w[1]  = pws[gid].i[1];
  w[2]  = pws[gid].i[2];
  w[3]  = pws[gid].i[3];
  w[4]  = pws[gid].i[4];
  w[5]  = pws[gid].i[5];
  w[6]  = pws[gid].i[6];
  w[7]  = pws[gid].i[7];
  w[8]  = 0;
  w[9]  = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len;

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 w_final[16];
    w_final[0]  = w[0];
    w_final[1]  = w[1];
    w_final[2]  = w[2];
    w_final[3]  = w[3];
    w_final[4]  = w[4];
    w_final[5]  = w[5];
    w_final[6]  = w[6];
    w_final[7]  = w[7];
    w_final[8]  = 0;
    w_final[9]  = 0;
    w_final[10] = 0;
    w_final[11] = 0;
    w_final[12] = 0;
    w_final[13] = 0;
    w_final[14] = 0;
    w_final[15] = 0;

    const u32 pw_len_final = apply_rules_vect (rules_buf, il_pos, w_final, pw_len);

    sha256_ctx_t sha_ctx;
    sha256_init (&sha_ctx);
    sha256_update_swap (&sha_ctx, w_final, pw_len_final);
    sha256_final (&sha_ctx);

    u32 prv_key[9];
    prv_key[0] = sha_ctx.h[7];
    prv_key[1] = sha_ctx.h[6];
    prv_key[2] = sha_ctx.h[5];
    prv_key[3] = sha_ctx.h[4];
    prv_key[4] = sha_ctx.h[3];
    prv_key[5] = sha_ctx.h[2];
    prv_key[6] = sha_ctx.h[1];
    prv_key[7] = sha_ctx.h[0];
    prv_key[8] = 0;

    u32 x[8], y[8];
    point_mul_xy (x, y, prv_key, &preG);

    u32 pub_key[16];
    pub_key[0]  = hc_swap32_S (x[7]);
    pub_key[1]  = hc_swap32_S (x[6]);
    pub_key[2]  = hc_swap32_S (x[5]);
    pub_key[3]  = hc_swap32_S (x[4]);
    pub_key[4]  = hc_swap32_S (x[3]);
    pub_key[5]  = hc_swap32_S (x[2]);
    pub_key[6]  = hc_swap32_S (x[1]);
    pub_key[7]  = hc_swap32_S (x[0]);
    pub_key[8]  = hc_swap32_S (y[7]);
    pub_key[9]  = hc_swap32_S (y[6]);
    pub_key[10] = hc_swap32_S (y[5]);
    pub_key[11] = hc_swap32_S (y[4]);
    pub_key[12] = hc_swap32_S (y[3]);
    pub_key[13] = hc_swap32_S (y[2]);
    pub_key[14] = hc_swap32_S (y[1]);
    pub_key[15] = hc_swap32_S (y[0]);

    u32 keccak_st[25] = { 0 };
    for (u32 i = 0; i < 16; i++) keccak_st[i] = hc_swap32_S (pub_key[i]);

    u64 st64[25] = { 0 };
    for (u32 i = 0; i < 8; i++)
      st64[i] = hl32_to_64_S (keccak_st[i * 2 + 1], keccak_st[i * 2 + 0]);

    keccak_transform_S (st64, 64, 200, 0x01, 256);

    u32 hash32[8];
    hash32[0] = l32_from_64_S (st64[0]);
    hash32[1] = h32_from_64_S (st64[0]);
    hash32[2] = l32_from_64_S (st64[1]);
    hash32[3] = h32_from_64_S (st64[1]);
    hash32[4] = l32_from_64_S (st64[2]);
    hash32[5] = h32_from_64_S (st64[2]);
    hash32[6] = l32_from_64_S (st64[3]);
    hash32[7] = h32_from_64_S (st64[3]);

    const u32 r0 = hash32[3];
    const u32 r1 = hash32[4];
    const u32 r2 = hash32[5];
    const u32 r3 = hash32[6];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
