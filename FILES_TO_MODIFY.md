# FILES REQUIRING MODIFICATION
## Hashcat Modules 35900-35904 Bug Fixes & Optimizations

---

## CRITICAL BUG FIXES (BLOCKER)

### Fix #1: Borrow Propagation in mod_512

**File:** `OpenCL/inc_ecc_secp256k1.cl`  
**Function:** `mod_512`  
**Lines:** 529-580 (approx)  

**Change:**  
Replace manual borrow propagation with temporary array to avoid read-after-write hazard.

**Testing:**  
- Affects scalar multiplication mod n  
- Test with edge-case scalars near group order boundary

---

### Fix #2: Left Shift Overflow in point_add

**File:** `OpenCL/inc_ecc_secp256k1.cl`  
**Function:** `point_add`  
**Lines:** 1388-1413  

**Change:**  
Capture carry before shift, apply omega reduction properly, add final modulo p check.

**Testing:**  
- Affects point addition for all ECC operations  
- Test with coordinates near field prime boundary

---

## HIGH-PRIORITY OPTIMIZATIONS

### Optimization #1: Move preG to Constant Memory

**Files to modify (ALL kernel variants):**  
```
OpenCL/m35900_a0-pure.cl  (lines 37-39, 81)
OpenCL/m35900_a1-pure.cl
OpenCL/m35900_a3-pure.cl
OpenCL/m35901_a0-pure.cl
OpenCL/m35901_a1-pure.cl
OpenCL/m35901_a3-pure.cl
OpenCL/m35902_a0-pure.cl
OpenCL/m35902_a1-pure.cl
OpenCL/m35902_a3-pure.cl
OpenCL/m35903_a0-pure.cl
OpenCL/m35903_a1-pure.cl
OpenCL/m35903_a3-pure.cl
OpenCL/m35904_a0-pure.cl
OpenCL/m35904_a1-pure.cl
OpenCL/m35904_a3-pure.cl
```

**Also modify:**  
`OpenCL/inc_ecc_secp256k1.h` - Update set_precomputed_basepoint_g declaration

**Change:**  
Replace per-thread private preG with shared constant memory preG.

**Expected Gain:** 20% speedup

---

### Optimization #2: Remove Redundant Copies

**File:** `OpenCL/inc_ecc_secp256k1.cl`  
**Functions:**  
- `point_double` (lines 1082-1244)
- `point_add` (lines 1269-1451)

**Change:**  
Eliminate initial coordinate copies, work with pointers directly.

**Expected Gain:** 10% speedup

---

## VERIFICATION STEPS

After making changes:

1. **Build:**
   ```bash
   make clean && make
   ```

2. **Self-Test:**
   ```bash
   ./hashcat -t -m 35900  # Bitcoin SHA-256
   ./hashcat -t -m 35901  # Bitcoin SHA3-256
   ./hashcat -t -m 35902  # Ethereum Keccak-256
   ./hashcat -t -m 35903  # Ethereum SHA-256
   ./hashcat -t -m 35904  # Ethereum SHA3-256
   ```

3. **Known-Answer Test:**
   ```bash
   # Create test file
   echo "1CkwUnESKuVFyn3PVm1fyyMtXx6CT2STg7" > bitcoin_test.hash
   echo "hashcat" > wordlist.txt
   
   # Should find: hashcat
   ./hashcat -a 0 -m 35900 bitcoin_test.hash wordlist.txt
   
   # Ethereum test
   echo "0x9c7002ea607c998e062793c420116b66f92421ac" > ethereum_test.hash
   ./hashcat -a 0 -m 35902 ethereum_test.hash wordlist.txt
   ```

4. **Benchmark:**
   ```bash
   ./hashcat -b -m 35900 -D 2  # GPU only
   ./hashcat -b -m 35902 -D 2
   ```

5. **Profile (Optional):**
   ```bash
   # Nvidia
   nvprof ./hashcat -a 0 -m 35900 test.hash wordlist.txt
   
   # AMD
   rocprof ./hashcat -a 0 -m 35900 test.hash wordlist.txt
   ```

---

## SUMMARY

**Files requiring changes:** 17 total
- 1 shared ECC library (inc_ecc_secp256k1.cl) - 2 critical bugs
- 15 kernel files - optimization only
- 1 header file - declaration update

**Engineering effort:**  
- Bug fixes: 2-3 hours
- Optimizations: 3-4 hours  
- Testing: 2-3 hours  
- **Total: 7-10 hours**

**Risk assessment:**  
- Critical bugs are well-isolated to 2 functions
- Optimizations are additive (can be done incrementally)
- All changes preserve API compatibility

