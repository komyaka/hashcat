# Private Key Processing Feature - Implementation Analysis

## Executive Summary

This document provides a comprehensive analysis of implementing a new feature in Hashcat to process private keys in hex format for ETH and BTC address generation. Based on exploration of the existing codebase, particularly the brainwallet modules (35900, 35901, 35902), we've identified the architecture and minimal changes needed.

## Current Architecture Overview

### 1. Attack Modes in Hashcat

**Location:** `include/types.h`, `src/dispatch.c`, `src/straight.c`

Hashcat supports multiple attack modes:
- **Mode 0 (ATTACK_MODE_STRAIGHT)**: Dictionary/wordlist attack
- **Mode 1 (ATTACK_MODE_COMBI)**: Combinator attack  
- **Mode 3 (ATTACK_MODE_BF)**: Brute-force with masks
- **Mode 6/7 (ATTACK_MODE_HYBRID1/2)**: Hybrid attacks
- **Mode 8 (ATTACK_MODE_GENERIC)**: Generic attack mode
- **Mode 9 (ATTACK_MODE_ASSOCIATION)**: Association/lookup mode

**Key Finding:** Hashcat already supports `--hex-wordlist` flag that converts hex-encoded input!

**Processing Flow:**
```
User Input → Attack Mode Dispatcher (dispatch.c)
           → Dictionary/Mask Generator (straight.c, mpsp.c)
           → Word Loading (wordlist.c)
           → GPU Kernel Execution
           → Result Comparison
```

### 2. Brainwallet Modules (35900, 35901, 35902)

**Current Implementation:**

| Module | Hash Type | Purpose |
|--------|-----------|---------|
| 35900  | SHA-256   | Bitcoin Brainwallet (P2PKH/Bech32/P2SH) |
| 35901  | SHA3-256  | Bitcoin Brainwallet (alternative hash) |
| 35902  | Keccak-256| Ethereum Brainwallet |

**Processing Pipeline:**
```
Passphrase → Hash Function → Private Key (256-bit)
                            ↓
                   secp256k1 Point Multiplication
                            ↓
                     Public Key (x,y)
                            ↓
                   Address Generation (BTC/ETH specific)
```

**Key Code Locations:**

- **CPU Modules:** `src/modules/module_35900.c`, `module_35902.c`
  - `module_hash_decode()`: Parse target address
  - `module_hash_encode()`: Format output
  - Module registration and metadata

- **GPU Kernels:** `OpenCL/m35900_a0-pure.cl`, `m35902_a0-pure.cl`
  - Actual cryptographic computation
  - Integrates with `inc_ecc_secp256k1.cl`

### 3. secp256k1 Implementation

**Location:** `OpenCL/inc_ecc_secp256k1.cl`, `include/emu_inc_ecc_secp256k1.h`

**Key Functions:**
- `point_mul_xy()`: Converts private key (scalar) to public key coordinates
- `point_mul()`: Wrapper that adds compression/parity byte
- Uses w-NAF (window Non-Adjacent Form) optimization
- Supports both compressed (33-byte) and uncompressed (65-byte) formats

**Coordinate Handling:**
- Compressed: `0x02 | 0x03` + 32-byte x-coordinate
- Uncompressed: `0x04` + 32-byte x + 32-byte y

### 4. Existing Hex Input Support

**CRITICAL DISCOVERY:** Hashcat already has `--hex-wordlist` flag!

**Location:** `src/wordlist.c`, `include/types.h`

**Function:** `convert_from_hex()` (line 20-52 in wordlist.c)
```c
size_t convert_from_hex (hashcat_ctx_t *hashcat_ctx, char *line_buf, const size_t line_len)
{
  if (line_len & 1) return (line_len); // not in hex
  
  if (hashconfig->opts_type & OPTS_TYPE_PT_HEX)
  {
    // Convert hex pairs to bytes
    for (i = 0, j = 0; j < line_len; i += 1, j += 2)
    {
      line_buf[i] = hex_to_u8 ((const u8 *) &line_buf[j]);
    }
    return (i);
  }
  // ... additional logic
}
```

**Usage:** `hashcat -m <mode> --hex-wordlist <hex_file> <hash_file>`

## Implementation Strategy

### Approach 1: **Minimal Change - Use Existing Infrastructure** (RECOMMENDED)

Create new hash modes that work with `--hex-wordlist`:

**New Module Numbers:**
- **35910**: Bitcoin Private Key (P2PKH compressed)
- **35911**: Bitcoin Private Key (P2PKH uncompressed)
- **35912**: Ethereum Private Key

**Changes Required:**

1. **New CPU Modules** (`src/modules/`)
   - Clone module_35900.c → module_35910.c (BTC compressed)
   - Clone module_35900.c → module_35911.c (BTC uncompressed)
   - Clone module_35902.c → module_35912.c (ETH)
   
   **Key Modifications:**
   - Set `OPTS_TYPE_PT_HEX` flag to enable hex processing
   - Skip the hash-to-privatekey step (input IS the private key)
   - Keep all address generation logic

2. **New GPU Kernels** (`OpenCL/`)
   - Clone m35900_a0-pure.cl → m35910_a0-pure.cl
   - Clone m35900_a0-pure.cl → m35911_a0-pure.cl
   - Clone m35902_a0-pure.cl → m35912_a0-pure.cl
   
   **Key Modifications:**
   - Remove SHA-256/Keccak-256 hashing step
   - Directly use input as 256-bit private key
   - Preserve secp256k1 point multiplication
   - Keep address generation (Base58Check/Keccak-256)

3. **Build System** (automatic via Makefile)
   - Modules auto-discovered by pattern matching
   - No Makefile changes needed

4. **Test Modules** (`tools/test_modules/`)
   - Create m35910.pm, m35911.pm, m35912.pm
   - Implement test vector generation
   - Verify with known private key → address mappings

**Implementation Pseudocode:**

```c
// In m35910_a0-pure.cl (BTC compressed)
KERNEL_FQ void m35910_mxx (KERN_ATTR_RULES ())
{
  // 1. Get candidate from wordlist (already in binary after --hex-wordlist)
  const u64 gid = get_global_id (0);
  u32 prv_key[8]; // 256-bit private key
  
  // Load from input buffer (pw_buf)
  prv_key[0] = pws[gid].i[0];
  prv_key[1] = pws[gid].i[1];
  // ... load full 32 bytes
  
  // 2. Validate private key is in valid range (1 to N-1)
  if (!validate_privkey(prv_key)) return;
  
  // 3. secp256k1 point multiplication
  secp256k1_t preG; // pre-computed base point
  u32 x[8], y[8];
  point_mul_xy(x, y, prv_key, &preG);
  
  // 4. Compress public key
  u32 pub_key_compressed[9];
  const u32 parity = y[0] & 1;
  pub_key_compressed[0] = (0x02 | parity) << 24 | (x[7] >> 8);
  // ... pack remaining x coordinate
  
  // 5. Generate address: HASH160(pub_key)
  u32 sha256_output[8];
  sha256_transform(pub_key_compressed, 33, sha256_output);
  
  u32 hash160[5];
  ripemd160_transform(sha256_output, 32, hash160);
  
  // 6. Compare with target digest
  if (hash160[0] == digests_buf[0] &&
      hash160[1] == digests_buf[1] &&
      hash160[2] == digests_buf[2] &&
      hash160[3] == digests_buf[3] &&
      hash160[4] == digests_buf[4])
  {
    if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, 0, digest_cur, gid, 0, 0, 0);
    }
  }
}
```

**For Ethereum (m35912):**
```c
// 3. secp256k1 gives us (x, y)
// 4. Use UNCOMPRESSED public key (no parity byte)
u32 pub_key_uncompressed[16]; // 64 bytes: x || y
// pack x coordinate (32 bytes)
// pack y coordinate (32 bytes)

// 5. Keccak-256(pub_key_uncompressed)
u32 keccak_output[8];
keccak_256_64(pub_key_uncompressed, keccak_output);

// 6. Take last 20 bytes as ETH address
u32 eth_address[5];
eth_address[0] = keccak_output[3];
eth_address[1] = keccak_output[4];
eth_address[2] = keccak_output[5];
eth_address[3] = keccak_output[6];
eth_address[4] = keccak_output[7];

// 7. Compare with target
// ...
```

### Approach 2: **Alternative - New Attack Mode** (More Complex)

Create a dedicated attack mode for "direct key processing":
- Define `ATTACK_MODE_PRIVKEY = 10`
- Modify `dispatch.c` to add new case
- Create specialized input handler

**Advantages:**
- More semantic clarity
- Can add validation/normalization

**Disadvantages:**
- Requires core changes to attack mode dispatcher
- More testing surface area
- Conflicts with principle of minimal change

**Verdict:** Not recommended for initial implementation.

## Input Format Specification

**Requirements:**
1. One private key per line
2. Hex encoding (64 hex characters = 32 bytes)
3. Support with/without "0x" prefix
4. Case insensitive

**Example Input File:**
```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
0xd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890
0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
```

**Pre-processing:**
- Strip "0x" / "0X" prefix if present → Done in `module_hash_decode()` (see module_35902.c:76-80)
- Convert to binary via `--hex-wordlist` flag → Handled by `convert_from_hex()`
- Validate length is exactly 32 bytes → Enforce in kernel

## Testing Strategy

### Unit Tests (Per Module)

**Test Vectors:**

1. **Bitcoin P2PKH Compressed (35910)**
```
Private Key: 0x0000000000000000000000000000000000000000000000000000000000000001
Public Key:  0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Address:     1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

2. **Bitcoin P2PKH Uncompressed (35911)**
```
Private Key: 0x0000000000000000000000000000000000000000000000000000000000000001
Public Key:  0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
Address:     1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm
```

3. **Ethereum (35912)**
```
Private Key: 0x0000000000000000000000000000000000000000000000000000000000000001
Public Key:  (uncompressed, no prefix)
Address:     0x7e5f4552091a69125d5dfcb7b8c2659029395bdf
```

### Integration Tests

1. **Basic Functionality**
```bash
# Create test input
echo "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" > privkeys.hex

# Create test hash (compute address for this privkey)
# BTC example
echo "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" > target_btc.txt

# Run hashcat
./hashcat -m 35910 --hex-wordlist target_btc.txt privkeys.hex
```

2. **Prefix Handling**
```bash
# Mix of formats
cat > privkeys_mixed.hex << EOF
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
0xd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890
EOF

./hashcat -m 35910 --hex-wordlist target.txt privkeys_mixed.hex
```

3. **Edge Cases**
- Maximum private key (N-1 for secp256k1)
- Minimum private key (1)
- Invalid keys (0, >= N) should be rejected

### Performance Validation

**Expected Performance:**
- Similar to existing brainwallet modes (35900, 35902)
- Bottleneck: secp256k1 point multiplication (~95% of compute time)
- Should achieve 100K-1M keys/sec on modern GPUs (mode-dependent)

## Build and Deployment

### Build Steps

```bash
# 1. Clean build
make clean

# 2. Compile (modules auto-discovered)
make

# 3. Verify new modules loaded
./hashcat --help | grep -A 3 "35910\|35911\|35912"
```

### Module Registration

Modules are automatically discovered by the build system via:
```makefile
MODULES := $(patsubst src/modules/module_%.c,%,$(wildcard src/modules/module_*.c))
```

No manual registration needed.

### Kernel Compilation

Kernels are JIT-compiled at runtime or pre-compiled:
- Naming convention: `m<mode>_a<attack_mode>-<variant>.cl`
- Auto-detected by kernel loader
- Cache in `~/.hashcat/kernels/`

## Security Considerations

### Private Key Validation

**MANDATORY:** Kernels MUST validate:
1. Private key != 0
2. Private key < N (secp256k1 order)
3. N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

**Implementation:**
```c
DECLSPEC bool validate_privkey(const u32 *prv_key)
{
  // Check not zero
  if (prv_key[0] == 0 && prv_key[1] == 0 && /* ... all zero */) return false;
  
  // Check < N (compare against SECP256K1_N from inc_ecc_secp256k1.h)
  // Implement 256-bit comparison
  return is_less_than_N(prv_key);
}
```

### Side-Channel Resistance

**Current Status:** Hashcat GPU kernels are NOT constant-time
- Acceptable for offline cracking use case
- Not suitable for key generation (not the use case here)
- Existing secp256k1 implementation has timing variations

**No Changes Needed:** This feature inherits existing security model.

### Input Sanitization

**File Processing:**
- `--hex-wordlist` automatically handles conversion
- Invalid hex chars → parsing error (handled by `hex_to_u8()`)
- Length validation enforced in kernel

## File Structure Summary

### Files to Create

```
src/modules/module_35910.c          # BTC P2PKH compressed
src/modules/module_35911.c          # BTC P2PKH uncompressed  
src/modules/module_35912.c          # ETH address

OpenCL/m35910_a0-pure.cl            # BTC compressed kernel
OpenCL/m35910_a1-pure.cl            # (optional: combinator variant)
OpenCL/m35910_a3-pure.cl            # (optional: brute-force variant)

OpenCL/m35911_a0-pure.cl            # BTC uncompressed kernel
OpenCL/m35912_a0-pure.cl            # ETH kernel

tools/test_modules/m35910.pm        # Perl test module (BTC compressed)
tools/test_modules/m35911.pm        # Perl test module (BTC uncompressed)
tools/test_modules/m35912.pm        # Perl test module (ETH)
```

### Files to Reference (Not Modify)

```
include/types.h                     # Attack mode definitions
include/convert.h                   # Hex conversion utilities
src/dispatch.c                      # Attack mode dispatcher
src/wordlist.c                      # Input file processing
src/straight.c                      # Dictionary attack logic
OpenCL/inc_ecc_secp256k1.cl         # secp256k1 implementation
OpenCL/inc_hash_sha256.cl           # SHA-256 for BTC
OpenCL/inc_hash_ripemd160.cl        # RIPEMD-160 for BTC
OpenCL/inc_hash_keccak.cl           # Keccak-256 for ETH
include/emu_inc_hash_base58.h       # Base58Check encoding
```

## Minimal Changes Summary

**Recommended Approach: 3 New Modules + Kernels**

### Files to Create: ~9 files
1. 3 CPU modules (one per address type)
2. 3-9 GPU kernels (1-3 per module, depending on attack modes supported)
3. 3 test modules

### Lines of Code Estimate
- **CPU modules**: ~250 lines each (cloned from existing)
- **GPU kernels**: ~200-300 lines each (simplified from brainwallet)
- **Test modules**: ~100 lines each
- **Total**: ~2,500-3,000 lines

### Core Changes: ZERO
- No modifications to `dispatch.c`, `wordlist.c`, or attack mode logic
- No new attack modes
- No build system changes
- Pure module addition

## Usage Examples

### Bitcoin P2PKH Compressed

```bash
# Create private key file (hex)
cat > privkeys.txt << EOF
0000000000000000000000000000000000000000000000000000000000000001
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
EOF

# Create target address file
echo "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH" > target.txt

# Run hashcat
./hashcat -m 35910 --hex-wordlist target.txt privkeys.txt

# With rules (e.g., increment lower byte)
./hashcat -m 35910 --hex-wordlist -r rules/increment.rule target.txt privkeys.txt
```

### Ethereum

```bash
# Private keys (with 0x prefix)
cat > eth_privkeys.txt << EOF
0x0000000000000000000000000000000000000000000000000000000000000001
0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
EOF

# Target addresses
cat > eth_targets.txt << EOF
0x7e5f4552091a69125d5dfcb7b8c2659029395bdf
0x9c7002ea607c998e062793c420116b66f92421ac
EOF

# Run
./hashcat -m 35912 --hex-wordlist eth_targets.txt eth_privkeys.txt
```

### Multiple Address Formats

```bash
# For BTC, test both compressed and uncompressed
./hashcat -m 35910 compressed_addrs.txt privkeys.txt    # Compressed (starts with 1)
./hashcat -m 35911 uncompressed_addrs.txt privkeys.txt  # Uncompressed (starts with 1)
```

## Next Steps

1. **Prototype Module 35910** (BTC compressed)
   - Clone module_35900.c
   - Add `OPTS_TYPE_PT_HEX` flag
   - Remove SHA-256 passphrase hashing
   - Test with known vectors

2. **Prototype Kernel**
   - Clone m35900_a0-pure.cl
   - Simplify: input → privkey validation → point_mul → address → compare
   - Test on CPU emulator first

3. **Create Test Module**
   - Implement known test vectors
   - Add to tools/test_modules/

4. **Validate Performance**
   - Benchmark vs existing brainwallet modes
   - Confirm GPU utilization

5. **Extend to Other Variants**
   - Module 35911 (BTC uncompressed)
   - Module 35912 (ETH)
   - Additional address formats (P2SH, Bech32) if needed

## References

### Code Files Analyzed
- `src/modules/module_35900.c` - Bitcoin brainwallet reference
- `src/modules/module_35902.c` - Ethereum brainwallet reference
- `OpenCL/m35902_a0-pure.cl` - Kernel implementation pattern
- `OpenCL/inc_ecc_secp256k1.cl` - Elliptic curve operations
- `src/dispatch.c` - Attack mode routing
- `src/wordlist.c` - Input processing with hex support
- `include/types.h` - Type definitions and constants

### Test Infrastructure
- `tools/test.sh` - Main test runner
- `tools/test.pl` - Perl test framework
- `tools/test_modules/*.pm` - Per-mode test generators
- `example*.sh` - Example test scripts

### Build System
- `Makefile` - Root makefile
- `src/Makefile` - Module compilation rules
- Module discovery: automatic via wildcard pattern matching

## Conclusion

The implementation is **straightforward** and follows established patterns:
1. Use existing `--hex-wordlist` flag for input conversion
2. Clone existing brainwallet modules (35900/35902)
3. Simplify kernels by removing passphrase hashing step
4. Reuse all secp256k1 and address generation logic
5. No core engine changes required

**Estimated Development Time:** 2-3 days for experienced hashcat developer
**Risk Level:** Low (pure module addition, no core changes)
**Performance:** Expected to match existing brainwallet modes (~100K-1M keys/sec GPU)
