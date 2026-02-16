# Private Key Processing - Architecture Flow Diagrams

## High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         HASHCAT CORE ENGINE                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌────────────────┐      ┌──────────────────┐      ┌─────────────┐ │
│  │  User Options  │─────▶│  Attack Mode     │─────▶│  Dispatcher │ │
│  │  Parser        │      │  Router          │      │  (dispatch.c)│ │
│  └────────────────┘      └──────────────────┘      └──────┬──────┘ │
│         │                                                   │        │
│         │ --hex-wordlist flag                              │        │
│         ▼                                                   ▼        │
│  ┌────────────────┐      ┌──────────────────┐      ┌─────────────┐ │
│  │   Wordlist     │      │  Module Loader   │      │   Kernel    │ │
│  │   Processor    │      │  (module_*.so)   │      │   Runtime   │ │
│  │  (wordlist.c)  │      │                  │      │  (OpenCL)   │ │
│  └────────────────┘      └──────────────────┘      └─────────────┘ │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

## Current Brainwallet Flow (Mode 35900/35902)

```
┌───────────────────────────────────────────────────────────────────────┐
│                      INPUT: Passphrase File                            │
│                      "hashcat"                                         │
│                      "password123"                                     │
│                      "correct horse battery staple"                    │
└────────────────────────────────┬──────────────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │   Dictionary Loader     │
                    │   (straight.c)          │
                    │   - Read line by line   │
                    │   - Apply rules         │
                    └────────────┬────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │   GPU Kernel Launch     │
                    │   (m35900_a0-pure.cl)   │
                    └────────────┬────────────┘
                                  │
                    ┌─────────────▼────────────┐
                    │  Per-GPU-Thread:         │
                    │                          │
                    │  1. Load passphrase      │
                    │     "hashcat"            │
                    │          │               │
                    │          ▼               │
                    │  2. SHA-256 Hash         │
                    │     (or Keccak-256)      │
                    │          │               │
                    │          ▼               │
                    │  3. Private Key (32B)    │
                    │     e3b0c442...52b855    │
                    │          │               │
                    │          ▼               │
                    │  4. secp256k1 Point Mul  │
                    │     point_mul_xy()       │
                    │          │               │
                    │          ▼               │
                    │  5. Public Key (x, y)    │
                    │          │               │
                    │          ▼               │
                    │  6. Address Generation   │
                    │     BTC: HASH160+Base58  │
                    │     ETH: Keccak+Last20   │
                    │          │               │
                    │          ▼               │
                    │  7. Compare with Target  │
                    │          │               │
                    │          ▼               │
                    │     Match? → Report!     │
                    └──────────────────────────┘
```

## Proposed Private Key Flow (New Modes 35910/35911/35912)

```
┌───────────────────────────────────────────────────────────────────────┐
│                   INPUT: Private Keys in HEX                           │
│                   "e3b0c44298fc1c149afbf4c8996fb92427ae4..."           │
│                   "0xd7a8fbb307d7809469ca9abcb0082e4f8d5..."           │
│                   "ABCDEF1234567890ABCDEF12345678..."                  │
└────────────────────────────────┬──────────────────────────────────────┘
                                  │
                    ┌─────────────▼────────────┐
                    │  --hex-wordlist flag      │
                    │  (user_options)           │
                    └─────────────┬────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │  convert_from_hex()     │
                    │  (wordlist.c:20-52)     │
                    │                         │
                    │  Input:                 │
                    │  "e3b0c442...52b855"    │
                    │                         │
                    │  Process:               │
                    │  - Strip 0x if present  │
                    │  - Convert hex pairs    │
                    │    "e3" → 0xe3          │
                    │    "b0" → 0xb0          │
                    │  - Pack into bytes      │
                    │                         │
                    │  Output: 32 bytes       │
                    │  [0xe3,0xb0,0xc4,...]   │
                    └────────────┬────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │   Dictionary Loader     │
                    │   (straight.c)          │
                    │   - Words already binary│
                    │   - Length = 32 bytes   │
                    └────────────┬────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │   GPU Kernel Launch     │
                    │   (m35910_a0-pure.cl)   │ ◄── NEW KERNEL
                    └────────────┬────────────┘
                                  │
                    ┌─────────────▼────────────┐
                    │  Per-GPU-Thread:         │
                    │                          │
                    │  1. Load binary input    │
                    │     (32 bytes)           │
                    │          │               │
                    │          ▼               │
                    │  ╔═══════════════════╗   │
                    │  ║ ⚠ SKIP HASHING ⚠  ║   │ ◄── KEY CHANGE
                    │  ╚═══════════════════╝   │
                    │          │               │
                    │          ▼               │
                    │  2. Validate Private Key │ ◄── NEW STEP
                    │     - Check != 0         │
                    │     - Check < N          │
                    │          │               │
                    │          ▼               │
                    │  3. secp256k1 Point Mul  │
                    │     point_mul_xy()       │
                    │          │               │
                    │          ▼               │
                    │  4. Public Key (x, y)    │
                    │          │               │
                    │          ▼               │
                    │  5. Address Generation   │
                    │     BTC: HASH160+Base58  │
                    │     ETH: Keccak+Last20   │
                    │          │               │
                    │          ▼               │
                    │  6. Compare with Target  │
                    │          │               │
                    │          ▼               │
                    │     Match? → Report!     │
                    └──────────────────────────┘
```

## Module Architecture Comparison

### Existing Brainwallet Module (35900)

```
┌────────────────────────────────────────────────────────┐
│              src/modules/module_35900.c                │
├────────────────────────────────────────────────────────┤
│                                                        │
│  ┌──────────────────────────────────────────────┐    │
│  │  Module Metadata                             │    │
│  │  - HASH_NAME: "Bitcoin Brainwallet"          │    │
│  │  - KERN_TYPE: 35900                          │    │
│  │  - ATTACK_EXEC: INSIDE_KERNEL                │    │
│  │  - SALT_TYPE: EMBEDDED                       │    │
│  │  - OPTS_TYPE: PT_GENERATE_LE                 │    │
│  └──────────────────────────────────────────────┘    │
│                                                        │
│  ┌──────────────────────────────────────────────┐    │
│  │  module_hash_decode()                        │    │
│  │  - Parse target address (Base58/Bech32)      │    │
│  │  - Extract HASH160 (20 bytes)                │    │
│  │  - Verify checksum                           │    │
│  └──────────────────────────────────────────────┘    │
│                                                        │
│  ┌──────────────────────────────────────────────┐    │
│  │  module_hash_encode()                        │    │
│  │  - Convert HASH160 back to address           │    │
│  │  - Add checksum                              │    │
│  │  - Base58Check encoding                      │    │
│  └──────────────────────────────────────────────┘    │
│                                                        │
└────────────────────────────────────────────────────────┘
         │
         │ Links to kernel
         ▼
┌────────────────────────────────────────────────────────┐
│           OpenCL/m35900_a0-pure.cl                     │
├────────────────────────────────────────────────────────┤
│                                                        │
│  KERNEL void m35900_m04()                             │
│  {                                                     │
│    // 1. Load passphrase from pw_buf                  │
│    // 2. SHA-256(passphrase) → private_key            │
│    // 3. point_mul_xy(private_key) → pub_key          │
│    // 4. HASH160(pub_key) → address_hash              │
│    // 5. Compare with digests_buf[]                   │
│  }                                                     │
│                                                        │
└────────────────────────────────────────────────────────┘
```

### New Private Key Module (35910)

```
┌────────────────────────────────────────────────────────┐
│              src/modules/module_35910.c                │ ◄── CLONE OF 35900
├────────────────────────────────────────────────────────┤
│                                                        │
│  ┌──────────────────────────────────────────────┐    │
│  │  Module Metadata                             │    │
│  │  - HASH_NAME: "Bitcoin Private Key (P2PKH)"  │    │ ◄── CHANGED
│  │  - KERN_TYPE: 35910                          │    │ ◄── CHANGED
│  │  - ATTACK_EXEC: INSIDE_KERNEL                │    │
│  │  - SALT_TYPE: NONE                           │    │ ◄── CHANGED
│  │  - OPTS_TYPE: PT_HEX | PT_GENERATE_LE        │    │ ◄── ADDED PT_HEX
│  └──────────────────────────────────────────────┘    │
│                                                        │
│  ┌──────────────────────────────────────────────┐    │
│  │  module_hash_decode()                        │    │
│  │  - Parse target address (Base58)             │    │ (UNCHANGED)
│  │  - Extract HASH160 (20 bytes)                │    │
│  │  - Verify checksum                           │    │
│  └──────────────────────────────────────────────┘    │
│                                                        │
│  ┌──────────────────────────────────────────────┐    │
│  │  module_hash_encode()                        │    │
│  │  - Convert HASH160 back to address           │    │ (UNCHANGED)
│  │  - Add checksum                              │    │
│  │  - Base58Check encoding                      │    │
│  └──────────────────────────────────────────────┘    │
│                                                        │
└────────────────────────────────────────────────────────┘
         │
         │ Links to NEW kernel
         ▼
┌────────────────────────────────────────────────────────┐
│           OpenCL/m35910_a0-pure.cl                     │ ◄── NEW FILE
├────────────────────────────────────────────────────────┤
│                                                        │
│  KERNEL void m35910_m04()                             │
│  {                                                     │
│    // 1. Load private_key from pw_buf (32 bytes)      │ ◄── CHANGED
│    // 2. ⚠ SKIP SHA-256 STEP ⚠                        │ ◄── REMOVED
│    // 3. Validate: 0 < private_key < N                │ ◄── ADDED
│    // 4. point_mul_xy(private_key) → pub_key          │
│    // 5. HASH160(pub_key) → address_hash              │
│    // 6. Compare with digests_buf[]                   │
│  }                                                     │
│                                                        │
└────────────────────────────────────────────────────────┘
```

## secp256k1 Point Multiplication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│          point_mul_xy(x, y, prv_key, preG)                      │
│          (OpenCL/inc_ecc_secp256k1.cl:2029-2162)                │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Input: Private Key (256-bit)  │
          │  k = prv_key[0..7]             │
          │  Example:                      │
          │  0x0000...0001 (scalar 1)      │
          └───────────────┬────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  convert_to_window_naf()       │
          │  - Convert k to w-NAF form     │
          │  - Window size = 4             │
          │  - Digits: {0, ±1, ±3, ±5, ±7} │
          └───────────────┬────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Initialize Point P            │
          │  - Load first w-NAF digit      │
          │  - P = preG[digit]             │
          │    (1G, 3G, 5G, or 7G)         │
          └───────────────┬────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Loop: Process w-NAF digits    │
          │  For each digit d in w-NAF:    │
          │    1. P = 2*P (point_double)   │
          │    2. If d != 0:               │
          │       P = P + preG[d]          │
          │       (point_add)              │
          └───────────────┬────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Convert Jacobian → Affine     │
          │  - P in Jacobian (X, Y, Z)     │
          │  - Compute Z_inv = 1/Z         │
          │  - x = X * Z_inv²              │
          │  - y = Y * Z_inv³              │
          └───────────────┬────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Output: Public Key (x, y)     │
          │  Example for k=1:              │
          │  x = 0x79be667e...16f81798      │
          │  y = 0x483ada77...0d4b8         │
          └────────────────────────────────┘
```

## Address Generation: Bitcoin vs Ethereum

### Bitcoin P2PKH Address Generation (Module 35910)

```
┌─────────────────────────────┐
│  Public Key (x, y)          │
│  33 bytes (compressed)      │
│  or 65 bytes (uncompressed) │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Compressed Format:         │
│  [parity_byte] [32-byte x]  │
│                             │
│  parity_byte:               │
│  0x02 if y is even          │
│  0x03 if y is odd           │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  SHA-256(pub_key)           │
│  → 32 bytes                 │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  RIPEMD-160(sha256_output)  │
│  → 20 bytes (HASH160)       │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Add version byte           │
│  0x00 + HASH160             │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  SHA-256(SHA-256(payload))  │
│  Take first 4 bytes         │
│  → checksum                 │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Append checksum            │
│  version + HASH160 + sum    │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Base58 Encoding            │
│  → "1BgGZ9tcN4rm9K..."      │
└─────────────────────────────┘
```

### Ethereum Address Generation (Module 35912)

```
┌─────────────────────────────┐
│  Public Key (x, y)          │
│  64 bytes (uncompressed)    │
│  NO parity byte prefix      │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Uncompressed Format:       │
│  [32-byte x] [32-byte y]    │
│  Total: 64 bytes            │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Keccak-256(pub_key)        │
│  → 32 bytes (256 bits)      │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Take Last 20 bytes         │
│  (bytes 12-31 of hash)      │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Hex Encode with 0x prefix  │
│  → "0x7e5f4552091a69..."    │
└─────────────────────────────┘
```

## Performance Flow

```
┌───────────────────────────────────────────────────────────┐
│                    Performance Bottlenecks                 │
└───────────────────────────────────────────────────────────┘

Input Processing (CPU):      ████ ~5% of time
  - File I/O
  - Hex conversion           (--hex-wordlist flag)
  - Buffer management

GPU Transfer:                ██ ~2% of time
  - Host → Device memory
  - Private keys (32 bytes each)
  - Batch size: 10K-100K keys

secp256k1 Point Mul (GPU):   ████████████████████ ~90% of time
  ⚠ MAIN BOTTLENECK
  - 256-bit modular arithmetic
  - w-NAF scalar conversion
  - Point doubling loop
  - Point addition
  - Modular inversion (Jacobian→Affine)

Address Hashing (GPU):       ███ ~3% of time
  - SHA-256 + RIPEMD-160 (BTC)
  - Keccak-256 (ETH)

Comparison:                  █ <1% of time
  - Memory read from digests_buf
  - Integer comparison

┌───────────────────────────────────────────────────────────┐
│              Expected Performance Numbers                  │
└───────────────────────────────────────────────────────────┘

GPU Model          | Keys/Second (Approx) | Notes
-------------------|----------------------|----------------------
NVIDIA RTX 4090    | ~800K - 1.2M        | Flagship consumer
NVIDIA RTX 3080    | ~500K - 700K        | High-end
AMD RX 7900 XTX    | ~400K - 600K        | High-end AMD
NVIDIA GTX 1080    | ~200K - 300K        | Older generation

Note: Performance similar to existing brainwallet modes (35900/35902)
      Bottleneck is secp256k1, not hashing difference
```

## Data Flow Through the System

```
┌──────────────────────────────────────────────────────────────────┐
│                        DATA STRUCTURES                            │
└──────────────────────────────────────────────────────────────────┘

File on Disk:
┌────────────────────────────────────────────────────────┐
│ privkeys.txt                                           │
│ "e3b0c44298fc1c149afbf4c8996fb92427ae41e4..."  (64 hex)│
│ "0xd7a8fbb307d7809469ca9abcb0082e4f8d5..."    (66 hex)│
└────────────────────────────────────────────────────────┘
                          │
                          │ read_file()
                          ▼
Memory (wl_data buffer):
┌────────────────────────────────────────────────────────┐
│ char wl_data->buf[]                                    │
│ "e3b0c44298fc1c149afbf4c8996fb92427ae41e4...\n"        │
│ "0xd7a8fbb307d7809469ca9abcb0082e4f8d5...\n"           │
└────────────────────────────────────────────────────────┘
                          │
                          │ convert_from_hex()
                          ▼
Binary words:
┌────────────────────────────────────────────────────────┐
│ u32 pw_buf[8][gid]                                     │
│ [0xe3, 0xb0, 0xc4, 0x42, ...] (32 bytes)               │
│ [0xd7, 0xa8, 0xfb, 0xb3, ...] (32 bytes)               │
└────────────────────────────────────────────────────────┘
                          │
                          │ memcpy to GPU
                          ▼
GPU Global Memory:
┌────────────────────────────────────────────────────────┐
│ GLOBAL_AS const pw_t *pws                              │
│ pws[0].i[0..7] = private_key_0                         │
│ pws[1].i[0..7] = private_key_1                         │
│ ...                                                    │
└────────────────────────────────────────────────────────┘
                          │
                          │ GPU thread reads
                          ▼
GPU Private Memory (per-thread):
┌────────────────────────────────────────────────────────┐
│ u32 prv_key[8]        // 256-bit private key           │
│ u32 x[8], y[8]        // Public key coordinates        │
│ u32 hash160[5]        // Address hash                  │
└────────────────────────────────────────────────────────┘
                          │
                          │ secp256k1 + hashing
                          ▼
Comparison:
┌────────────────────────────────────────────────────────┐
│ GLOBAL_AS const digest_t *digests_buf (target hashes)  │
│ Compare hash160[] with digests_buf[digest_cur]         │
│   IF MATCH: atomic_inc(hashes_shown[])                 │
│            mark_hash() → store result                  │
└────────────────────────────────────────────────────────┘
                          │
                          │ memcpy from GPU
                          ▼
Output (potfile):
┌────────────────────────────────────────────────────────┐
│ hashcat.potfile                                        │
│ 1BgGZ9tcN4rm9K...:e3b0c44298fc1c149afbf4c8996fb924... │
└────────────────────────────────────────────────────────┘
```

## Implementation Diff Summary

```diff
=== New Files ===
+ src/modules/module_35910.c          (BTC P2PKH compressed)
+ src/modules/module_35911.c          (BTC P2PKH uncompressed)
+ src/modules/module_35912.c          (ETH addresses)
+ OpenCL/m35910_a0-pure.cl            (BTC compressed kernel)
+ OpenCL/m35911_a0-pure.cl            (BTC uncompressed kernel)
+ OpenCL/m35912_a0-pure.cl            (ETH kernel)
+ tools/test_modules/m35910.pm        (Test vectors)
+ tools/test_modules/m35911.pm
+ tools/test_modules/m35912.pm

=== Modified Files ===
(NONE - Zero core changes!)

=== Key Changes in New Modules ===

--- module_35900.c (reference)
+++ module_35910.c (new)

  static const char *HASH_NAME         = "Bitcoin Private Key (P2PKH Compressed)";
- static const u64   KERN_TYPE         = 35900;
+ static const u64   KERN_TYPE         = 35910;
  static const u64   OPTS_TYPE         = OPTS_TYPE_STOCK_MODULE
+                                      | OPTS_TYPE_PT_HEX
                                       | OPTS_TYPE_PT_GENERATE_LE;
- static const u32   SALT_TYPE         = SALT_TYPE_EMBEDDED;
+ static const u32   SALT_TYPE         = SALT_TYPE_NONE;

--- m35900_a0-pure.cl (reference)
+++ m35910_a0-pure.cl (new)

  KERNEL_FQ void m35910_mxx (KERN_ATTR_RULES ())
  {
-   // SHA-256 hashing
-   sha256_ctx_t ctx;
-   sha256_init (&ctx);
-   sha256_update (&ctx, w, pw_len);
-   sha256_final (&ctx);
-   
-   u32 prv_key[8];
-   prv_key[0] = ctx.h[0];
-   prv_key[1] = ctx.h[1];
-   // ... (derive private key from hash)

+   // Direct private key input (already converted by --hex-wordlist)
+   u32 prv_key[8];
+   prv_key[0] = pws[gid].i[0];
+   prv_key[1] = pws[gid].i[1];
+   // ... (load full 32 bytes)
+   
+   // Validate private key range
+   if (!validate_privkey(prv_key)) return;
    
    // Rest of code UNCHANGED (secp256k1 + address gen)
    secp256k1_t preG;
    u32 x[8], y[8];
    point_mul_xy (x, y, prv_key, &preG);
    // ...
  }
```

## Conclusion

The architecture is **clean and modular**:
- Reuses 95% of existing brainwallet code
- Leverages `--hex-wordlist` for input conversion
- Only kernel change: remove hashing step
- No modifications to core engine required
- Expected development time: 2-3 days
