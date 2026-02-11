# preG Initialization Fix - Summary

## Objective
Add preG initialization to OpenCL kernel files for hash modes 35901-35904 (Bitcoin brainwallet variants).

## Changes Applied

### Files Modified (15 total)
All files in the `OpenCL/` directory:
- m35900_a0-pure.cl, m35900_a1-pure.cl, m35900_a3-pure.cl (reference - completed)
- m35901_a0-pure.cl, m35901_a1-pure.cl, m35901_a3-pure.cl
- m35902_a0-pure.cl, m35902_a1-pure.cl, m35902_a3-pure.cl
- m35903_a0-pure.cl, m35903_a1-pure.cl, m35903_a3-pure.cl
- m35904_a0-pure.cl, m35904_a1-pure.cl, m35904_a3-pure.cl

### Pattern Applied

In each file, the following initialization was added to **both** kernel functions (mxx and sxx):

```c
secp256k1_t preG;

set_precomputed_basepoint_g (&preG);
```

### Placement Strategy

The placement varies by attack mode and context:

#### a0 Files (KERN_ATTR_RULES)
**mxx function:**
- After `COPY_PW (pws[gid]);` and before loop/salt access
- For files with `addr_type`: After COPY_PW, before `const u32 addr_type = ...`
- For files without `addr_type`: After COPY_PW, before `for (u32 il_pos = ...)`

**sxx function:**
- After `search[]` declaration and before `COPY_PW (pws[gid]);`

#### a1 Files (KERN_ATTR_BASIC)
**mxx function:**
- After password buffer copy loop and before loop/salt access
  - For SHA3-based (m35901, m35902, m35904): After `for (u32 idx = 0; idx < 16; idx++) { w[idx] = ... }`, before `const u32 addr_type` or main loop
  - For SHA256-based (m35903): After gid check, before sha256_ctx_t initialization

**sxx function:**
- After `search[]` declaration, before pw_len or sha256_ctx_t initialization

#### a3 Files (KERN_ATTR_VECTOR)
**mxx function:**
- After password buffer copy loop, before `u32x w0l = w[0];`
  - For SHA3-based: After `for (u32 i = 0, idx = 0; ...)` loop
  - For SHA256-based (m35903): After gid check, before pw_len declaration

**sxx function:**
- After `search[]` declaration, before `const u32 pw_len = ...`

## Verification

All files verified with:
- ✓ `secp256k1_t preG;` declaration present
- ✓ `set_precomputed_basepoint_g (&preG);` initialization present
- ✓ `point_mul_xy (x, y, prv_key, &preG);` usage present
- ✓ Initialization placed BEFORE first usage
- ✓ Both mxx and sxx functions updated
- ✓ Consistent indentation maintained
- ✓ No syntax errors introduced

## Technical Notes

1. **Prerequisite Changes** (already applied):
   - `SECP256K1_TMPS_TYPE` changed from `CONSTANT_AS` to `PRIVATE_AS`
   - All references to `&preG_const` changed to `&preG`

2. **Why This Is Needed**:
   - `preG` is used by `point_mul_xy()` for elliptic curve operations
   - The precomputed basepoint G must be initialized before use
   - Without initialization, kernel execution would reference uninitialized memory

3. **Attack Mode Differences**:
   - **a0 (rules)**: Single password, rule applied
   - **a1 (combinator)**: Two password halves combined
   - **a3 (brute-force/mask)**: Vectorized operations, right-side variations

## Hash Mode Variants

- **35900**: SHA-256 → P2PKH (original)
- **35901**: SHA3-256 → P2PKH  
- **35902**: Keccak-256 → P2PKH
- **35903**: SHA-256 → P2WPKH-P2SH
- **35904**: Keccak-256 → P2WPKH-P2SH

Each uses secp256k1 elliptic curve operations, hence requires preG initialization.
