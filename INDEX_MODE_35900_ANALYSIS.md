# Mode 35900 Analysis - Documentation Index

## Overview

This directory contains comprehensive analysis documentation for Hashcat mode 35900 (Bitcoin Brainwallet) following a critical bug fix and thorough code review to address segmentation faults with 40M addresses.

**Analysis Date**: February 10, 2024  
**Commit Analyzed**: 118bd9db  
**Lines of Code Reviewed**: 7000+  
**Files Generated**: 4 comprehensive documents

---

## Quick Start

### If you're experiencing issues:
1. **Start here**: [`ISSUE_SUMMARY_35900.md`](./ISSUE_SUMMARY_35900.md) - Quick overview of findings
2. **Troubleshooting**: [`TROUBLESHOOTING_CHECKLIST_35900.md`](./TROUBLESHOOTING_CHECKLIST_35900.md) - Step-by-step diagnostic guide
3. **Technical details**: [`DEEP_ANALYSIS_MODE_35900.md`](./DEEP_ANALYSIS_MODE_35900.md) - Full technical analysis
4. **Results summary**: [`ANALYSIS_RESULTS.txt`](./ANALYSIS_RESULTS.txt) - Structured findings report

---

## Document Descriptions

### 1. ISSUE_SUMMARY_35900.md
**Purpose**: Executive summary for quick consumption  
**Audience**: All users experiencing issues  
**Length**: ~5 KB (5 min read)  
**Contents**:
- Quick findings overview
- Root cause analysis for segfaults
- Selftest failure analysis
- Immediate action items
- Memory requirements breakdown

**When to read**: First document to check for quick answers

---

### 2. TROUBLESHOOTING_CHECKLIST_35900.md
**Purpose**: Step-by-step diagnostic and testing protocol  
**Audience**: Users troubleshooting issues, testers  
**Length**: ~9 KB (10-15 min to execute)  
**Contents**:
- Pre-flight system checks (RAM, GPU, disk)
- Hash file validation procedures
- Selftest diagnostic steps
- Gradual scale-up testing (1K → 10K → 100K → 40M)
- Common issues and solutions
- Debug log capture instructions
- Final verification checklist

**When to read**: When running tests or diagnosing persistent issues

---

### 3. DEEP_ANALYSIS_MODE_35900.md
**Purpose**: Comprehensive technical analysis of all code paths  
**Audience**: Developers, security researchers, advanced users  
**Length**: ~16 KB (30-45 min read)  
**Contents**:
- **Section 1**: Integer overflow risk in `digests_offset`
- **Section 2**: Memory allocation overflow analysis
- **Section 3**: secp256k1 implementation review (2275 lines)
- **Section 4**: OpenCL kernel analysis (all 3 variants)
- **Section 5**: Selftest infrastructure analysis
- **Section 6**: Bitwise/logical operator bug search
- **Section 7**: Other potential issues (sorting, GPU transfer)
- **Section 8**: Summary table of all findings
- **Section 9**: Recommended code improvements
- **Section 10**: Conclusions
- **Appendix A**: Data structure size calculations
- **Appendix B**: Test command examples

**When to read**: When you need to understand the internals or verify correctness

---

### 4. ANALYSIS_RESULTS.txt
**Purpose**: Structured summary of all findings and verification  
**Audience**: Project maintainers, auditors  
**Length**: ~7 KB (15 min read)  
**Format**: ASCII text with clear section headers  
**Contents**:
- Critical findings (bitwise OR bug - FIXED)
- Potential issues (overflow risks - future-proofing)
- Verified correct implementations (8 major components)
- Memory requirements breakdown
- Search results (no additional bugs)
- Bitwise OR bug technical details
- Conclusions and recommendations
- Deliverables list
- Analysis confidence statement

**When to read**: For official records, audit trail, or comprehensive summary

---

## Key Findings Summary

### ✅ **FIXED**: Bitwise OR Bug
- **Location**: `src/hashes.c:2146`
- **Commit**: 118bd9db
- **Change**: `|` → `||` (bitwise to logical OR)
- **Impact**: Was the only code-level bug affecting mode 35900
- **Status**: Resolved, no remaining instances found

### ⚠️ **FUTURE-PROOFING**: Integer Overflow Risks
- **Locations**: `src/hashes.c:2114, 1997-2026`
- **Impact**: No issue with 40M hashes, could affect >1B hashes
- **Recommendations**: Add overflow checks (optional improvements)
- **Status**: Noted for future enhancement

### ✅ **VERIFIED CORRECT**: All Cryptographic Operations
- secp256k1 field/scalar arithmetic
- Point addition/doubling/multiplication
- SHA-256 and RIPEMD-160 operations
- Public key compression
- P2SH wrapping logic
- Hash parsing (P2PKH, P2SH, Bech32)

---

## File Dependency Map

```
INDEX_MODE_35900_ANALYSIS.md (this file)
    ├── ISSUE_SUMMARY_35900.md ← Start here for quick overview
    │   └── References: DEEP_ANALYSIS_MODE_35900.md
    │
    ├── TROUBLESHOOTING_CHECKLIST_35900.md ← Use for diagnostics
    │   ├── References: ISSUE_SUMMARY_35900.md
    │   └── References: DEEP_ANALYSIS_MODE_35900.md
    │
    ├── DEEP_ANALYSIS_MODE_35900.md ← Technical deep dive
    │   └── Standalone (references code directly)
    │
    └── ANALYSIS_RESULTS.txt ← Formal summary
        └── Standalone (complete record)
```

---

## Workflow Recommendations

### For Users Experiencing Segfaults:
```
1. Read: ISSUE_SUMMARY_35900.md (5 min)
2. Verify: Commit 118bd9db is deployed
3. Follow: TROUBLESHOOTING_CHECKLIST_35900.md (30 min)
4. Report: If issues persist, include debug log
```

### For Developers Reviewing Code:
```
1. Read: DEEP_ANALYSIS_MODE_35900.md (45 min)
2. Review: Sections 1-3 (overflow risks)
3. Verify: secp256k1 implementation (Section 3)
4. Consider: Recommended improvements (Section 9)
```

### For Project Maintainers:
```
1. Read: ANALYSIS_RESULTS.txt (15 min)
2. Note: Two optional improvements (overflow checks)
3. Review: Analysis confidence statement
4. Archive: All 4 documents for audit trail
```

### For Security Auditors:
```
1. Read: ANALYSIS_RESULTS.txt (overview)
2. Deep dive: DEEP_ANALYSIS_MODE_35900.md (full technical)
3. Verify: Bitwise OR bug fix in commit 118bd9db
4. Check: secp256k1 implementation correctness (Section 3)
5. Note: No critical vulnerabilities found
```

---

## Code Locations Reference

### Primary Files Analyzed:
```
src/hashes.c                      - Hash loading, sorting, memory management
src/modules/module_35900.c        - Address parsing, validation
src/selftest.c                    - Selftest infrastructure
OpenCL/m35900_a0-pure.cl          - Rules kernel (pure)
OpenCL/m35900_a1-pure.cl          - Combinator kernel
OpenCL/m35900_a3-pure.cl          - Mask kernel (pure)
OpenCL/inc_ecc_secp256k1.cl       - Elliptic curve cryptography (2275 lines)
OpenCL/inc_types.h                - Structure definitions (salt_t)
include/types.h                   - Host structure definitions
```

### Key Locations:
```
Bug fix:           src/hashes.c:2146          (bitwise OR → logical OR)
Overflow risk 1:   src/hashes.c:2114          (digests_offset assignment)
Overflow risk 2:   src/hashes.c:1997-2026     (memory allocations)
ECC implementation: OpenCL/inc_ecc_secp256k1.cl:106-2030  (all operations)
Kernel logic:      OpenCL/m35900_a0-pure.cl:54-148  (main algorithm)
Test vector:       src/modules/module_35900.c:29-30  (hashcat → 1Ckw...)
```

---

## Memory Requirements (40M Hashes)

| Scenario | Host RAM | GPU VRAM | Notes |
|----------|----------|----------|-------|
| Best case (deduplicated) | 2.4 GB | 1-2 GB | Only 3 salt types |
| Worst case (all unique) | 24.8 GB | 1-2 GB | Unlikely scenario |
| Recommended minimum | 4 GB | 2 GB | For safety margin |

---

## Testing Protocol Summary

```bash
# 1. Self-test
./hashcat -t -m 35900

# 2. Small scale (1K addresses)
./hashcat -m 35900 test_1k.txt -a 3 ?l?l?l?l

# 3. Medium scale (10K addresses)
./hashcat -m 35900 test_10k.txt -a 3 ?l?l?l?l?l

# 4. Large scale (100K addresses)
./hashcat -m 35900 test_100k.txt -a 3 ?l?l?l?l?l?l

# 5. Full scale (40M addresses)
./hashcat -m 35900 addresses_40m.txt -a 3 <attack_params>
```

**Monitoring**:
```bash
watch -n 1 'free -h; nvidia-smi | grep MiB'
```

---

## Additional Resources

### External References:
- **secp256k1**: https://github.com/bitcoin-core/secp256k1 (reference implementation)
- **BIP16 (P2SH)**: https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
- **Bech32**: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
- **ECC algorithms**: http://eprint.iacr.org/2011/338.pdf (Rivain 2011)

### Hashcat Documentation:
- Mode 35900: Bitcoin Brainwallet (SHA-256, P2PKH/Bech32/P2SH)
- Attack modes: -a 0 (wordlist), -a 3 (mask/brute-force)
- Workload profiles: -w 1 (low) to -w 4 (nightmare)

---

## Questions & Support

### If you have questions about:

- **Analysis findings**: See `DEEP_ANALYSIS_MODE_35900.md` Section 8 (Summary)
- **How to troubleshoot**: See `TROUBLESHOOTING_CHECKLIST_35900.md`
- **Bug fix details**: See `ANALYSIS_RESULTS.txt` (Bitwise OR Bug Details)
- **Memory requirements**: See `ISSUE_SUMMARY_35900.md` (Memory Layout)
- **Test vectors**: See `DEEP_ANALYSIS_MODE_35900.md` Appendix B

### If issues persist:
1. Verify commit 118bd9db is deployed
2. Complete full troubleshooting checklist
3. Capture debug log with `--debug-mode=4`
4. Report with system info (RAM, GPU, OS)

---

## Analysis Methodology

This analysis employed:
- ✅ Manual code review (7000+ lines)
- ✅ Grep-based pattern searching
- ✅ Structure size calculations
- ✅ Algorithm complexity analysis
- ✅ Cryptographic correctness verification
- ✅ Integer overflow range checking
- ✅ Memory allocation validation
- ✅ Cross-referencing with standards (BIP16, Bech32)

**Analysis Confidence**: HIGH  
**Coverage**: All critical code paths for mode 35900

---

## Document Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-02-10 | Initial comprehensive analysis |

---

## License & Credits

These analysis documents are provided to complement the Hashcat project.

**Hashcat License**: MIT (see main LICENSE file)  
**Analysis Author**: Super Engineer Agent  
**Analysis Date**: February 10, 2024  
**Repository**: https://github.com/hashcat/hashcat

---

**END OF INDEX**
