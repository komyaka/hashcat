# Implementation Guide: Private Key Processing for Hashcat

## Quick Start

This guide provides step-by-step instructions for implementing private key processing (hex format) for BTC and ETH addresses in Hashcat.

## Prerequisites

- Familiarity with C and OpenCL
- Understanding of secp256k1 elliptic curve
- Hashcat source code checked out
- Development environment set up (gcc, OpenCL headers)

## Phase 1: Implement Bitcoin P2PKH Compressed (Module 35910)

### Step 1.1: Create CPU Module

**File:** `src/modules/module_35910.c`

```c
/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"

#include "emu_inc_hash_base58.h"

// Module metadata
static const u32   ATTACK_EXEC       = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0         = 0;
static const u32   DGST_POS1         = 1;
static const u32   DGST_POS2         = 2;
static const u32   DGST_POS3         = 3;
static const u32   DGST_SIZE         = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY     = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME         = "Bitcoin Private Key → P2PKH (compressed)";
static const u64   KERN_TYPE         = 35910;
static const u32   OPTI_TYPE         = 0;
static const u64   OPTS_TYPE         = OPTS_TYPE_STOCK_MODULE
                                     | OPTS_TYPE_PT_GENERATE_LE
                                     | OPTS_TYPE_PT_HEX;  // ◄── ENABLE HEX INPUT
static const u32   SALT_TYPE         = SALT_TYPE_NONE;  // ◄── NO SALT
static const char *ST_PASS           = "0000000000000000000000000000000000000000000000000000000000000001";
static const char *ST_HASH           = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

// Standard module function exports
u32         module_attack_exec       (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category     (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type         (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash           (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass           (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

// Password constraints
u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 64; // 64 hex characters = 32 bytes
  return pw_min;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 64; // Exactly 32 bytes
  return pw_max;
}

// Decode target Bitcoin address (P2PKH format)
int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  // Initialize
  memset (salt, 0, sizeof (salt_t));

  // Bitcoin P2PKH address: Base58Check encoded
  // Format: 1... (starts with '1')
  // Length: typically 26-35 characters
  
  if (line_len < 26 || line_len > 35) return (PARSER_HASH_LENGTH);
  if (line_buf[0] != '1') return (PARSER_SIGNATURE_UNMATCHED);

  // Decode Base58Check
  u8 address_bytes[25]; // version(1) + hash160(20) + checksum(4)
  
  const int decoded_len = base58_decode (base58_to_int, (const u8 *) line_buf, line_len, address_bytes);
  
  if (decoded_len != 25) return (PARSER_HASH_LENGTH);
  
  // Verify version byte
  if (address_bytes[0] != 0x00) return (PARSER_HASH_VALUE);
  
  // Verify checksum
  u8 checksum_calculated[32];
  sha256_ctx_t ctx;
  
  sha256_init (&ctx);
  sha256_update (&ctx, address_bytes, 21); // version + hash160
  sha256_final (&ctx);
  
  sha256_init (&ctx);
  sha256_update (&ctx, ctx.h, 32);
  sha256_final (&ctx);
  
  if (memcmp (ctx.h, address_bytes + 21, 4) != 0) return (PARSER_HASH_VALUE);
  
  // Extract HASH160 (20 bytes) → 5 u32 words
  digest[0] = byte_swap_32 (((u32 *) (address_bytes + 1))[0]);
  digest[1] = byte_swap_32 (((u32 *) (address_bytes + 1))[1]);
  digest[2] = byte_swap_32 (((u32 *) (address_bytes + 1))[2]);
  digest[3] = byte_swap_32 (((u32 *) (address_bytes + 1))[3]);
  digest[4] = byte_swap_32 (((u32 *) (address_bytes + 1))[4]);

  return (PARSER_OK);
}

// Encode HASH160 back to Bitcoin address
int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  // Build payload: version(1) + hash160(20)
  u8 payload[25];
  payload[0] = 0x00; // P2PKH version

  u32 hash160_swapped[5];
  hash160_swapped[0] = byte_swap_32 (digest[0]);
  hash160_swapped[1] = byte_swap_32 (digest[1]);
  hash160_swapped[2] = byte_swap_32 (digest[2]);
  hash160_swapped[3] = byte_swap_32 (digest[3]);
  hash160_swapped[4] = byte_swap_32 (digest[4]);
  
  memcpy (payload + 1, hash160_swapped, 20);

  // Calculate checksum
  sha256_ctx_t ctx;
  sha256_init (&ctx);
  sha256_update (&ctx, payload, 21);
  sha256_final (&ctx);
  
  sha256_init (&ctx);
  sha256_update (&ctx, ctx.h, 32);
  sha256_final (&ctx);
  
  memcpy (payload + 21, ctx.h, 4);

  // Base58 encode
  base58_encode (int_to_base58, payload, 25, (u8 *) line_buf);

  const int line_len = strlen (line_buf);

  return line_len;
}

// Module initialization
void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = MODULE_DEFAULT;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
```

### Step 1.2: Create GPU Kernel

**File:** `OpenCL/m35910_a0-pure.cl`

```c
/**
 * Author......: See docs/credits.txt
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
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#endif

// Validate private key is in valid range: 1 <= k < N
DECLSPEC bool validate_privkey (PRIVATE_AS const u32 *prv_key)
{
  // Check not zero
  bool is_zero = true;
  for (int i = 0; i < 8; i++)
  {
    if (prv_key[i] != 0)
    {
      is_zero = false;
      break;
    }
  }
  if (is_zero) return false;
  
  // Check < N (secp256k1 order)
  // N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  const u32 SECP256K1_N[8] =
  {
    0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6,
    0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff
  };
  
  // Compare from most significant to least significant
  for (int i = 7; i >= 0; i--)
  {
    if (prv_key[i] > SECP256K1_N[i]) return false;
    if (prv_key[i] < SECP256K1_N[i]) return true;
  }
  
  // Equal to N is invalid
  return false;
}

KERNEL_FQ void m35910_mxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc table for base58
   */

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 0
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 8;
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  secp256k1_t preG; // pre-computed base point multiples

  point_get_coords (&preG);

  SYNC_THREADS ();

  /**
   * Load private key from input (already converted from hex by --hex-wordlist)
   */
  
  u32 prv_key[8];
  
  // Load 32 bytes (8 u32 words) from password buffer
  prv_key[0] = pws[gid].i[0];
  prv_key[1] = pws[gid].i[1];
  prv_key[2] = pws[gid].i[2];
  prv_key[3] = pws[gid].i[3];
  prv_key[4] = pws[gid].i[4];
  prv_key[5] = pws[gid].i[5];
  prv_key[6] = pws[gid].i[6];
  prv_key[7] = pws[gid].i[7];
  
  // Swap endianness if needed (private keys are big-endian)
  prv_key[0] = hc_swap32_S (prv_key[0]);
  prv_key[1] = hc_swap32_S (prv_key[1]);
  prv_key[2] = hc_swap32_S (prv_key[2]);
  prv_key[3] = hc_swap32_S (prv_key[3]);
  prv_key[4] = hc_swap32_S (prv_key[4]);
  prv_key[5] = hc_swap32_S (prv_key[5]);
  prv_key[6] = hc_swap32_S (prv_key[6]);
  prv_key[7] = hc_swap32_S (prv_key[7]);

  /**
   * Validate private key
   */
  
  if (!validate_privkey (prv_key)) return;

  /**
   * secp256k1 point multiplication: pub_key = G * prv_key
   */
  
  u32 x[8];
  u32 y[8];

  point_mul_xy (x, y, prv_key, &preG);

  /**
   * Compress public key
   * Format: [parity_byte] [32-byte x-coordinate]
   */
  
  u32 pub_key[9]; // 33 bytes compressed

  const u32 parity = (y[0] & 1) ? 0x03 : 0x02;
  
  // Pack: parity byte in highest byte of first word
  pub_key[0] = (x[7] >> 8) | (parity << 24);
  pub_key[1] = (x[7] << 24) | (x[6] >> 8);
  pub_key[2] = (x[6] << 24) | (x[5] >> 8);
  pub_key[3] = (x[5] << 24) | (x[4] >> 8);
  pub_key[4] = (x[4] << 24) | (x[3] >> 8);
  pub_key[5] = (x[3] << 24) | (x[2] >> 8);
  pub_key[6] = (x[2] << 24) | (x[1] >> 8);
  pub_key[7] = (x[1] << 24) | (x[0] >> 8);
  pub_key[8] = (x[0] << 24);

  /**
   * Generate Bitcoin address: HASH160(pub_key)
   * HASH160 = RIPEMD160(SHA256(pub_key))
   */
  
  // Step 1: SHA-256
  sha256_ctx_t ctx_sha256;

  sha256_init (&ctx_sha256);
  sha256_update (&ctx_sha256, pub_key, 33);
  sha256_final (&ctx_sha256);

  // Step 2: RIPEMD-160
  ripemd160_ctx_t ctx_ripemd160;

  ripemd160_init (&ctx_ripemd160);
  
  u32 tmp[16];
  tmp[0] = ctx_sha256.h[0];
  tmp[1] = ctx_sha256.h[1];
  tmp[2] = ctx_sha256.h[2];
  tmp[3] = ctx_sha256.h[3];
  tmp[4] = ctx_sha256.h[4];
  tmp[5] = ctx_sha256.h[5];
  tmp[6] = ctx_sha256.h[6];
  tmp[7] = ctx_sha256.h[7];
  
  ripemd160_update (&ctx_ripemd160, tmp, 32);
  ripemd160_final (&ctx_ripemd160);

  /**
   * Compare with target digest
   */
  
  const u32 r0 = ctx_ripemd160.h[0];
  const u32 r1 = ctx_ripemd160.h[1];
  const u32 r2 = ctx_ripemd160.h[2];
  const u32 r3 = ctx_ripemd160.h[3];
  const u32 r4 = ctx_ripemd160.h[4];

  COMPARE_M_SCALAR (r0, r1, r2, r3);
}

KERNEL_FQ void m35910_sxx (KERN_ATTR_RULES ())
{
  // Similar to _mxx but optimized for single hash comparison
  // (Implementation details similar to above)
}
```

### Step 1.3: Create Test Module

**File:** `tools/test_modules/m35910.pm`

```perl
#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256);
use Digest::RIPEMD160 qw (ripemd160);

sub module_constraints { [[32, 32], [0, 0], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  
  # Expect 64 hex characters (32 bytes)
  return unless length($word) == 64;
  return unless $word =~ /^[0-9a-fA-F]{64}$/;
  
  # Convert hex string to binary
  my $prv_key = pack("H*", $word);
  
  # secp256k1 point multiplication (using external library or reference implementation)
  # For testing, use a known library like Crypt::Secp256k1 or call Python script
  
  # Example using Python subprocess (requires python3 + ecdsa library)
  my $python_script = <<'PYTHON';
import sys
from ecdsa import SigningKey, SECP256k1
import hashlib

prv_key_hex = sys.argv[1]
prv_key_bytes = bytes.fromhex(prv_key_hex)

sk = SigningKey.from_string(prv_key_bytes, curve=SECP256k1)
vk = sk.get_verifying_key()

# Compressed public key
pub_key_bytes = vk.to_string()
x = int.from_bytes(pub_key_bytes[:32], 'big')
y = int.from_bytes(pub_key_bytes[32:], 'big')
parity = 0x02 if y % 2 == 0 else 0x03
pub_key_compressed = bytes([parity]) + x.to_bytes(32, 'big')

# HASH160
sha256_hash = hashlib.sha256(pub_key_compressed).digest()
hash160 = hashlib.new('ripemd160', sha256_hash).digest()

# Base58Check encode
def base58_encode(data):
    import base58
    return base58.b58encode_check(data).decode('ascii')

address = base58_encode(b'\x00' + hash160)
print(address)
PYTHON

  my $address = `python3 -c '$python_script' $word 2>/dev/null`;
  chomp $address;
  
  return unless $address;
  return unless $address =~ /^1/;  # P2PKH starts with '1'
  
  my $hash = sprintf ("%s", $address);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless length ($word) == 64;
  return unless $word =~ /^[0-9a-fA-F]{64}$/;

  my $word_packed = pack ("H*", $word);

  return ($word_packed, $word);
}

1;
```

### Step 1.4: Test Your Implementation

```bash
# 1. Compile
cd /path/to/hashcat
make clean
make

# 2. Verify module loaded
./hashcat --help | grep 35910

# 3. Create test files
echo "0000000000000000000000000000000000000000000000000000000000000001" > test_privkey.txt
echo "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH" > test_address.txt

# 4. Run hashcat
./hashcat -m 35910 --hex-wordlist -a 0 test_address.txt test_privkey.txt

# Expected output:
# 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH:0000000000000000000000000000000000000000000000000000000000000001
```

## Phase 2: Implement Bitcoin P2PKH Uncompressed (Module 35911)

### Changes from 35910:
1. **Module metadata:** Change `KERN_TYPE` to 35911
2. **Kernel:** Use uncompressed public key (65 bytes: 0x04 + x + y)

**Key difference in kernel:**
```c
// Uncompressed format
u32 pub_key[17]; // 65 bytes: 0x04 + 32-byte x + 32-byte y

pub_key[0] = 0x04000000 | (x[7] >> 8);  // Prefix 0x04
pub_key[1] = (x[7] << 24) | (x[6] >> 8);
// ... pack full x coordinate (32 bytes)
pub_key[8] = (x[0] << 24) | (y[7] >> 8);
// ... pack full y coordinate (32 bytes)
pub_key[16] = y[0] << 24;

// Rest is same: SHA-256 → RIPEMD-160 → compare
```

## Phase 3: Implement Ethereum (Module 35912)

### Changes from BTC:
1. **No Base58:** Use hex encoding with "0x" prefix
2. **Uncompressed key without 0x04 prefix:** Just x || y (64 bytes)
3. **Keccak-256 instead of SHA-256+RIPEMD-160**
4. **Address = last 20 bytes of Keccak-256(pub_key)**

**Kernel snippet:**
```c
// Ethereum: uncompressed public key (NO 0x04 prefix)
u32 pub_key[16]; // 64 bytes: x || y

pub_key[0] = x[7];
pub_key[1] = x[6];
// ... pack x (32 bytes)
pub_key[8] = y[7];
// ... pack y (32 bytes)

// Keccak-256
u64 keccak_st[25] = { 0 };
keccak_256_64 (pub_key, keccak_st);

// Extract last 20 bytes (words 12-16 of state, but extract correctly)
u32 eth_address[5];
eth_address[0] = (u32)(keccak_st[3] >> 32);  // Extract correctly based on layout
eth_address[1] = (u32)(keccak_st[4]);
eth_address[2] = (u32)(keccak_st[4] >> 32);
eth_address[3] = (u32)(keccak_st[5]);
eth_address[4] = (u32)(keccak_st[5] >> 32);

// Compare
COMPARE_M_SCALAR (eth_address[0], eth_address[1], eth_address[2], eth_address[3]);
```

## Testing Checklist

### Unit Tests
- [ ] Module loads without errors
- [ ] Known test vectors pass
- [ ] Invalid private keys rejected (0, >= N)
- [ ] Handles 0x prefix in input
- [ ] Handles uppercase/lowercase hex

### Integration Tests
- [ ] Works with `-a 0` (straight) mode
- [ ] Works with `--hex-wordlist` flag
- [ ] Output format matches expected
- [ ] Potfile stores correct format

### Performance Tests
- [ ] Benchmark runs successfully
- [ ] Performance comparable to mode 35900
- [ ] No memory leaks
- [ ] GPU utilization near 100%

## Common Issues and Solutions

### Issue 1: "Invalid password length"
**Solution:** Ensure `module_pw_min/max` returns 64 (for hex input), and `OPTS_TYPE_PT_HEX` is set.

### Issue 2: "No matches found" (but should match)
**Solution:** Check endianness handling. Private keys and coordinates may need byte swapping.

### Issue 3: Kernel compilation error
**Solution:** Verify all includes are present, especially `inc_ecc_secp256k1.cl`.

### Issue 4: Slow performance
**Solution:** Check GPU occupancy. secp256k1 is register-heavy; may need tuning.

## Next Steps

1. Implement remaining modules (35911, 35912)
2. Add support for additional formats (P2SH, Bech32)
3. Optimize kernel performance
4. Add comprehensive test suite
5. Document usage in official docs

## References

- Module 35900 source: `src/modules/module_35900.c`
- Kernel reference: `OpenCL/m35900_a0-pure.cl`
- secp256k1 implementation: `OpenCL/inc_ecc_secp256k1.cl`
- Test vector sources: blockchain.info, etherscan.io

## Support

For issues, refer to:
- Hashcat forums: https://hashcat.net/forum/
- GitHub issues: https://github.com/hashcat/hashcat/issues
- Documentation: https://hashcat.net/wiki/
