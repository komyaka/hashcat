/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 * 
 * Kernel for module 35910: Ethereum Address Lookup (Bloom Filter)
 * 
 * GPU-accelerated ETH address checking using secp256k1 + Keccak-256
 */

//#define NEW_SIMD_CODE

#define SECP256K1_TMPS_TYPE PRIVATE_AS

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_keccak.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#include M2S(INCLUDE_PATH/inc_bloom_filter.cl)
#endif

/**
 * ETH address generation from private key:
 * 1. Private key (32 bytes)
 * 2. Public key = secp256k1 point multiplication (uncompressed, 64 bytes)
 * 3. Address = last 20 bytes of Keccak-256(public_key)
 * 4. Check against bloom filter
 */

KERNEL_FQ void m35910_mxx (KERN_ATTR_RULES ())
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * Initialize secp256k1 base point
   */

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  COPY_PW (pws[gid]);

  /**
   * Main loop over rules/candidates
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t p = PASTE_PW;

    p.pw_len = apply_rules (rules_buf[il_pos].cmds, p.i, p.pw_len);

    /**
     * Step 1: Derive private key from password using SHA-256
     * (This follows brainwallet standard)
     */

    sha256_ctx_t sha_ctx;

    sha256_init        (&sha_ctx);
    sha256_update_swap (&sha_ctx, p.i, p.pw_len);
    sha256_final       (&sha_ctx);

    // Private key (big-endian to little-endian for secp256k1)
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

    /**
     * Step 2: EC point multiplication to get public key
     * pub_key = G * prv_key
     */

    u32 x[8];
    u32 y[8];

    point_mul_xy (x, y, prv_key, &preG);

    /**
     * Step 3: Build uncompressed public key (64 bytes = x || y)
     * ETH uses uncompressed format (no 0x04 prefix for hash)
     */

    u32 pub_key[16];

    // X coordinate (32 bytes) - convert to big-endian
    pub_key[0]  = hc_swap32_S (x[7]);
    pub_key[1]  = hc_swap32_S (x[6]);
    pub_key[2]  = hc_swap32_S (x[5]);
    pub_key[3]  = hc_swap32_S (x[4]);
    pub_key[4]  = hc_swap32_S (x[3]);
    pub_key[5]  = hc_swap32_S (x[2]);
    pub_key[6]  = hc_swap32_S (x[1]);
    pub_key[7]  = hc_swap32_S (x[0]);

    // Y coordinate (32 bytes) - convert to big-endian
    pub_key[8]  = hc_swap32_S (y[7]);
    pub_key[9]  = hc_swap32_S (y[6]);
    pub_key[10] = hc_swap32_S (y[5]);
    pub_key[11] = hc_swap32_S (y[4]);
    pub_key[12] = hc_swap32_S (y[3]);
    pub_key[13] = hc_swap32_S (y[2]);
    pub_key[14] = hc_swap32_S (y[1]);
    pub_key[15] = hc_swap32_S (y[0]);

    /**
     * Step 4: Keccak-256 hash of public key (64 bytes)
     */

    u32 keccak_st[25] = { 0 };

    // Keccak-256 of 64-byte public key
    keccak_st[0]  = hc_swap32_S (pub_key[0]);
    keccak_st[1]  = hc_swap32_S (pub_key[1]);
    keccak_st[2]  = hc_swap32_S (pub_key[2]);
    keccak_st[3]  = hc_swap32_S (pub_key[3]);
    keccak_st[4]  = hc_swap32_S (pub_key[4]);
    keccak_st[5]  = hc_swap32_S (pub_key[5]);
    keccak_st[6]  = hc_swap32_S (pub_key[6]);
    keccak_st[7]  = hc_swap32_S (pub_key[7]);
    keccak_st[8]  = hc_swap32_S (pub_key[8]);
    keccak_st[9]  = hc_swap32_S (pub_key[9]);
    keccak_st[10] = hc_swap32_S (pub_key[10]);
    keccak_st[11] = hc_swap32_S (pub_key[11]);
    keccak_st[12] = hc_swap32_S (pub_key[12]);
    keccak_st[13] = hc_swap32_S (pub_key[13]);
    keccak_st[14] = hc_swap32_S (pub_key[14]);
    keccak_st[15] = hc_swap32_S (pub_key[15]);

    // Keccak expects 64-bit words, convert u32 pairs
    u64 st64[25] = { 0 };

    for (u32 i = 0; i < 8; i++)
    {
      st64[i] = hl32_to_64_S (keccak_st[i * 2 + 1], keccak_st[i * 2 + 0]);
    }

    // Keccak-256 finalization
    keccak_transform_S (st64, 64, 200, 0x01, 256);

    /**
     * Step 5: Extract last 20 bytes as ETH address
     * Keccak output is in 64-bit words, we need bytes [12..31] of the 32-byte hash
     */

    u32 eth_address[5];

    // st64[0..7] contains the 256-bit hash
    // We want bytes [12..31] = last 20 bytes
    // Word layout: st64[1] has bytes [8..15], st64[2] has bytes [16..23], st64[3] has bytes [24..31]

    const u32 addr_word0 = h32_from_64_S (st64[1]);  // Bytes 12-15 (high half of st64[1], skip low 4 bytes)
    const u32 addr_word1 = l32_from_64_S (st64[2]);  // Bytes 16-19
    const u32 addr_word2 = h32_from_64_S (st64[2]);  // Bytes 20-23
    const u32 addr_word3 = l32_from_64_S (st64[3]);  // Bytes 24-27
    const u32 addr_word4 = h32_from_64_S (st64[3]);  // Bytes 28-31

    // Actually need to shift: Keccak output[12:31] is the address
    // st64[1] = bytes 8-15 (u64, little-endian on most GPUs)
    // We need to extract bytes 12-31 from the 32-byte hash

    // Simplify: convert st64 to u32 array and extract
    u32 hash32[8];
    hash32[0] = l32_from_64_S (st64[0]);
    hash32[1] = h32_from_64_S (st64[0]);
    hash32[2] = l32_from_64_S (st64[1]);
    hash32[3] = h32_from_64_S (st64[1]);
    hash32[4] = l32_from_64_S (st64[2]);
    hash32[5] = h32_from_64_S (st64[2]);
    hash32[6] = l32_from_64_S (st64[3]);
    hash32[7] = h32_from_64_S (st64[3]);

    // Address is hash32[3..7] (bytes 12-31)
    eth_address[0] = hash32[3];
    eth_address[1] = hash32[4];
    eth_address[2] = hash32[5];
    eth_address[3] = hash32[6];
    eth_address[4] = hash32[7];

    /**
     * Step 6: Compare against target or check bloom filter
     * For now, compare directly against digest (single address mode)
     */

    const u32 r0 = eth_address[0];
    const u32 r1 = eth_address[1];
    const u32 r2 = eth_address[2];
    const u32 r3 = eth_address[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m35910_sxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t p = PASTE_PW;

    p.pw_len = apply_rules (rules_buf[il_pos].cmds, p.i, p.pw_len);

    sha256_ctx_t sha_ctx;

    sha256_init        (&sha_ctx);
    sha256_update_swap (&sha_ctx, p.i, p.pw_len);
    sha256_final       (&sha_ctx);

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

    u32 x[8];
    u32 y[8];

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

    keccak_st[0]  = hc_swap32_S (pub_key[0]);
    keccak_st[1]  = hc_swap32_S (pub_key[1]);
    keccak_st[2]  = hc_swap32_S (pub_key[2]);
    keccak_st[3]  = hc_swap32_S (pub_key[3]);
    keccak_st[4]  = hc_swap32_S (pub_key[4]);
    keccak_st[5]  = hc_swap32_S (pub_key[5]);
    keccak_st[6]  = hc_swap32_S (pub_key[6]);
    keccak_st[7]  = hc_swap32_S (pub_key[7]);
    keccak_st[8]  = hc_swap32_S (pub_key[8]);
    keccak_st[9]  = hc_swap32_S (pub_key[9]);
    keccak_st[10] = hc_swap32_S (pub_key[10]);
    keccak_st[11] = hc_swap32_S (pub_key[11]);
    keccak_st[12] = hc_swap32_S (pub_key[12]);
    keccak_st[13] = hc_swap32_S (pub_key[13]);
    keccak_st[14] = hc_swap32_S (pub_key[14]);
    keccak_st[15] = hc_swap32_S (pub_key[15]);

    u64 st64[25] = { 0 };

    for (u32 i = 0; i < 8; i++)
    {
      st64[i] = hl32_to_64_S (keccak_st[i * 2 + 1], keccak_st[i * 2 + 0]);
    }

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
