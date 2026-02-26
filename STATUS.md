# STATUS

## PROBLEM
Full verification and bug fixes for hashcat modules 35900, 35901, 35902, 35903, 35904, 35910, 35912 (Bitcoin/Ethereum brainwallet and private key modules).

## ACCEPTANCE CRITERIA
- All 7 modules compile without errors
- Module 35910 correctly derives the Bitcoin P2PKH address from a raw hex private key (self-test: prv=0x000...0001 → 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)
- Module 35912 correctly derives the Ethereum address from a raw hex private key (self-test: prv=0x000...0001 → 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf)
- Ethereum address encode roundtrip is idempotent for modules 35902/35903/35904/35912

## CONSTRAINTS
- Do not change the fundamental algorithm or purpose of any module
- Minimal changes only

## IN SCOPE
- OpenCL/m35910_a0-pure.cl, OpenCL/m35910_a1-pure.cl, OpenCL/m35910_a3-pure.cl
- OpenCL/m35912_a0-pure.cl, OpenCL/m35912_a1-pure.cl, OpenCL/m35912_a3-pure.cl
- src/modules/module_35902.c, module_35903.c, module_35904.c, module_35912.c

## OUT OF SCOPE
- Modules 35900, 35901 (no bugs found)
- Any other hash modes

## RUN/TEST COMMANDS
```
make modules/module_35902.so modules/module_35903.so modules/module_35904.so modules/module_35910.so modules/module_35912.so
```
Verify Python encode logic:
```
python3 -c "..." (see IMPLEMENTATION LOG)
```

---

## ORCHESTRATION
TBD

## SCOPE
TBD

## RISKS
TBD

## DESIGN
TBD

## INTERFACES
TBD

## DATAFLOW
TBD

## EDGE CASES
TBD

## PERFORMANCE NOTES
TBD

## TEST PLAN
TBD

## NOTES / BLOCKERS
TBD

---

## IMPLEMENTATION LOG

### Bug 1 — Private key byte order in m35910 and m35912 (CRITICAL)

**Root cause**: In modules 35910 (Bitcoin Private Key) and 35912 (Ethereum Private Key), the OpenCL kernels loaded the secp256k1 private key directly from `p.i[]` / `c[]` / `w[]` without any byte-order conversion. hashcat stores decoded hex passwords in LE word format (first byte in the LSB of word 0), but `point_mul_xy` expects `k[0]` = LSW (least significant 32-bit word in BE byte order) and `k[7]` = MSW.

**Fix**: Replace `prv_key[i] = src[i]` with `prv_key[i] = hc_swap32_S(src[7-i])` in all 6 kernel files (a0/a1/a3 × m35910/m35912), both mxx and sxx functions.

**Verification**:
- For private key 1 (`0x000...001`): `p.i[7] = 0x01000000` (LE), `hc_swap32_S(p.i[7]) = 0x00000001` = correct LSW
- For private key 1: the resulting Bitcoin address is `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` ✓
- For private key 1: the resulting Ethereum address is `0x7e5f4552091a69125d5dfcb7b8c2659029395bdf` ✓

### Bug 2 — Ethereum address encode byte order in modules 35902, 35903, 35904, 35912

**Root cause**: `module_hash_decode` stores Ethereum addresses using `hex_to_u32` (hashcat LE convention: first byte in LSB). `module_hash_encode` printed via `%08x` without converting back, producing byte-swapped output. This broke potfile roundtrips and verify mode.

**Fix**: Added `byte_swap_32()` in `module_hash_encode` before each `snprintf` `%08x` argument.

**Verification**: `byte_swap_32(hex_to_u32("9c7002ea"))` = `0x9c7002ea` → printed correctly as `9c7002ea` ✓

### Files changed
- `OpenCL/m35910_a0-pure.cl` — both mxx/sxx
- `OpenCL/m35910_a1-pure.cl` — both mxx/sxx
- `OpenCL/m35910_a3-pure.cl` — both mxx/sxx
- `OpenCL/m35912_a0-pure.cl` — both mxx/sxx
- `OpenCL/m35912_a1-pure.cl` — both mxx/sxx
- `OpenCL/m35912_a3-pure.cl` — both mxx/sxx
- `src/modules/module_35902.c` — encode fix
- `src/modules/module_35903.c` — encode fix
- `src/modules/module_35904.c` — encode fix
- `src/modules/module_35912.c` — encode fix

### Build command and result
```
make modules/module_35902.so modules/module_35903.so modules/module_35904.so modules/module_35910.so modules/module_35912.so
# → exits 0, no errors or warnings
```

---

## AUDIT FINDINGS
TBD

## CHECKLIST
- [ ] Acceptance criteria mapped and verified
- [ ] Build command executed and recorded
- [ ] Tests executed and recorded
- [ ] Lint/format policy respected (if applicable)
- [ ] No scope creep detected
- [ ] Edge cases reviewed
- [ ] Security sanity check (as applicable)

## VERDICT
TBD
