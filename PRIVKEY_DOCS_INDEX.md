# Hashcat Private Key Processing Feature - Documentation Index

## Overview

This repository contains comprehensive documentation for implementing a private key processing feature in Hashcat that reads private keys in hex format and generates BTC/ETH addresses for comparison.

## 📚 Documentation Structure

### 1. **EXECUTIVE_SUMMARY.md** ⭐ START HERE
   - **Size:** 13 KB
   - **Audience:** Project managers, decision makers, anyone wanting a high-level overview
   - **Contents:**
     - Key findings from codebase exploration
     - Implementation feasibility assessment
     - Effort estimates and risk analysis
     - Quick reference guide
   - **Read time:** 10-15 minutes

### 2. **PRIVKEY_IMPLEMENTATION_ANALYSIS.md** 📊 TECHNICAL DEEP DIVE
   - **Size:** 17 KB  
   - **Audience:** Software architects, lead developers
   - **Contents:**
     - Current architecture analysis
     - Attack mode system explanation
     - Brainwallet module internals
     - secp256k1 integration details
     - Implementation strategy comparison
     - Input format specification
     - Testing strategy
     - Build system overview
   - **Read time:** 30-40 minutes

### 3. **ARCHITECTURE_FLOW.md** 🎨 VISUAL GUIDE
   - **Size:** 25 KB
   - **Audience:** Developers, system designers
   - **Contents:**
     - High-level system architecture diagrams
     - Data flow visualizations
     - Current vs proposed flow comparison
     - Module architecture diagrams
     - secp256k1 point multiplication flow
     - BTC vs ETH address generation comparison
     - Performance bottleneck analysis
     - Implementation diff summary
   - **Read time:** 20-30 minutes

### 4. **IMPLEMENTATION_GUIDE.md** 💻 PRACTICAL CODING GUIDE
   - **Size:** 24 KB
   - **Audience:** Developers implementing the feature
   - **Contents:**
     - Step-by-step implementation instructions
     - Complete code templates for:
       - CPU module (module_35910.c)
       - GPU kernel (m35910_a0-pure.cl)
       - Test module (m35910.pm)
     - Testing procedures
     - Common issues and solutions
     - Test vectors
   - **Read time:** 45-60 minutes + coding time

## 📖 Reading Recommendations

### For Project Planning
1. Read: **EXECUTIVE_SUMMARY.md**
2. Skim: **PRIVKEY_IMPLEMENTATION_ANALYSIS.md** (sections 1-3)
3. Review: Effort estimates and timeline

### For System Design
1. Read: **EXECUTIVE_SUMMARY.md**
2. Study: **ARCHITECTURE_FLOW.md**
3. Reference: **PRIVKEY_IMPLEMENTATION_ANALYSIS.md** (sections 1-4)

### For Implementation
1. Quick read: **EXECUTIVE_SUMMARY.md**
2. Follow: **IMPLEMENTATION_GUIDE.md** (Phase 1)
3. Reference: **ARCHITECTURE_FLOW.md** (for data structures)
4. Consult: **PRIVKEY_IMPLEMENTATION_ANALYSIS.md** (for edge cases)

### For Testing/QA
1. Read: **EXECUTIVE_SUMMARY.md** (test vectors section)
2. Follow: **IMPLEMENTATION_GUIDE.md** (Testing Checklist)
3. Reference: **PRIVKEY_IMPLEMENTATION_ANALYSIS.md** (Testing Strategy)

## 🎯 Key Findings Summary

### ✅ Feature is Fully Feasible

**Why:**
- Hashcat already has `--hex-wordlist` flag for hex input conversion
- secp256k1 implementation is production-ready and GPU-accelerated
- BTC and ETH address generation code already exists in brainwallet modules
- Modular architecture allows adding new modes without core changes

### 📊 Implementation Scope

| Metric | Value |
|--------|-------|
| **New Files** | 9 (3 modules, 3-6 kernels, 3 tests) |
| **Modified Files** | 0 (zero core changes) |
| **Lines of Code** | ~2,000-2,500 |
| **Development Time** | 2-3 days |
| **Testing Time** | 1-2 days |
| **Risk Level** | Low |

### 🏗️ Architecture

**Approach:** Clone existing brainwallet modules (35900, 35902) and remove the hashing step.

```
Brainwallet Flow:
Passphrase → Hash → Private Key → secp256k1 → Public Key → Address

New Flow:
Hex Input → Private Key → secp256k1 → Public Key → Address
     ↑                           ↑
--hex-wordlist        Direct from input
```

### 📝 New Modules

| Module | Purpose | Base |
|--------|---------|------|
| **35910** | Bitcoin Private Key → P2PKH (compressed) | 35900 |
| **35911** | Bitcoin Private Key → P2PKH (uncompressed) | 35900 |
| **35912** | Ethereum Private Key → Address | 35902 |

## 🚀 Quick Start Guide

### For Developers

```bash
# 1. Read executive summary
cat EXECUTIVE_SUMMARY.md

# 2. Follow implementation guide
cat IMPLEMENTATION_GUIDE.md

# 3. Start coding (Phase 1)
# - Create src/modules/module_35910.c
# - Create OpenCL/m35910_a0-pure.cl
# - Create tools/test_modules/m35910.pm

# 4. Build and test
make clean && make
./hashcat -m 35910 --help
```

### Usage Example

```bash
# Create hex private key file
echo "0000000000000000000000000000000000000000000000000000000000000001" > keys.txt

# Create target address file
echo "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH" > target.txt

# Run hashcat
./hashcat -m 35910 --hex-wordlist target.txt keys.txt

# Expected output:
# 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH:0000000000000000000000000000000000000000000000000000000000000001
# Status.........: Cracked
```

## 🔬 Technical Highlights

### Attack Modes
- Mode 0 (STRAIGHT): Dictionary/wordlist attack ✅ **Use this**
- Mode 3 (BF): Brute-force with masks
- Mode 8 (GENERIC): Generic attack mode

### Existing Infrastructure
- `--hex-wordlist` flag: Converts hex input to binary ✅
- `convert_from_hex()`: Automatic hex-to-binary conversion
- `OPTS_TYPE_PT_HEX`: Module flag to enable hex processing

### secp256k1 Implementation
- Location: `OpenCL/inc_ecc_secp256k1.cl` (~2,350 lines)
- Function: `point_mul_xy()` - Private key → Public key
- Optimization: w-NAF (window Non-Adjacent Form)
- Performance: ~100K-1M keys/sec on modern GPUs

### Address Generation
- **Bitcoin:** SHA-256 → RIPEMD-160 → Base58Check
- **Ethereum:** Keccak-256 → Last 20 bytes → Hex with 0x

## 🧪 Test Vectors

### Bitcoin (Module 35910)
```
Private Key: 0000000000000000000000000000000000000000000000000000000000000001
Address:     1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

### Ethereum (Module 35912)
```
Private Key: 0000000000000000000000000000000000000000000000000000000000000001
Address:     0x7e5f4552091a69125d5dfcb7b8c2659029395bdf
```

## 📈 Performance Expectations

| GPU | Keys/Second |
|-----|-------------|
| RTX 4090 | ~800K-1.2M |
| RTX 3080 | ~500K-700K |
| RX 7900 XTX | ~400K-600K |
| GTX 1080 | ~200K-300K |

**Bottleneck:** secp256k1 point multiplication (~90% of compute time)

## 🔒 Security Considerations

### Private Key Validation (Required)
1. ✅ Private key != 0
2. ✅ Private key < N (secp256k1 order)
3. ✅ Reject invalid keys in kernel

### Side-Channel Resistance
- ⚠️ Hashcat kernels are NOT constant-time (by design for performance)
- ✅ Acceptable for offline cracking use case
- ❌ Not suitable for online key generation (not the intended use)

## 📁 File Structure

```
hashcat/
├── src/
│   └── modules/
│       ├── module_35910.c          # ← NEW: BTC compressed
│       ├── module_35911.c          # ← NEW: BTC uncompressed
│       └── module_35912.c          # ← NEW: ETH
├── OpenCL/
│   ├── m35910_a0-pure.cl           # ← NEW: BTC compressed kernel
│   ├── m35911_a0-pure.cl           # ← NEW: BTC uncompressed kernel
│   ├── m35912_a0-pure.cl           # ← NEW: ETH kernel
│   └── inc_ecc_secp256k1.cl        # (existing, reused)
├── tools/
│   └── test_modules/
│       ├── m35910.pm               # ← NEW: Test module
│       ├── m35911.pm               # ← NEW
│       └── m35912.pm               # ← NEW
└── docs/                           # ← THIS DOCUMENTATION
    ├── INDEX.md                    # (this file)
    ├── EXECUTIVE_SUMMARY.md
    ├── PRIVKEY_IMPLEMENTATION_ANALYSIS.md
    ├── ARCHITECTURE_FLOW.md
    └── IMPLEMENTATION_GUIDE.md
```

## 🎓 Learning Path

### Beginner (New to Hashcat)
1. **Day 1:** Read EXECUTIVE_SUMMARY.md
2. **Day 2:** Study ARCHITECTURE_FLOW.md (focus on diagrams)
3. **Day 3:** Review existing brainwallet module (src/modules/module_35900.c)
4. **Day 4+:** Follow IMPLEMENTATION_GUIDE.md

### Intermediate (Familiar with Hashcat)
1. **Hour 1:** Skim EXECUTIVE_SUMMARY.md
2. **Hour 2-3:** Read PRIVKEY_IMPLEMENTATION_ANALYSIS.md
3. **Hour 4:** Review ARCHITECTURE_FLOW.md (data flow section)
4. **Day 2+:** Implement following IMPLEMENTATION_GUIDE.md

### Advanced (Hashcat Developer)
1. **30 min:** Read EXECUTIVE_SUMMARY.md
2. **1 hour:** Skim IMPLEMENTATION_GUIDE.md for code templates
3. **Start coding:** Use documents as reference

## 🛠️ Development Checklist

### Phase 1: Prototype (Module 35910)
- [ ] Create `src/modules/module_35910.c`
- [ ] Create `OpenCL/m35910_a0-pure.cl`
- [ ] Create `tools/test_modules/m35910.pm`
- [ ] Compile and verify module loads
- [ ] Test with known vectors
- [ ] Benchmark performance

### Phase 2: Extend
- [ ] Implement module 35911 (BTC uncompressed)
- [ ] Implement module 35912 (Ethereum)
- [ ] Add comprehensive test suite
- [ ] Performance optimization

### Phase 3: Polish
- [ ] Documentation updates
- [ ] Code review
- [ ] Security audit
- [ ] Community testing

## 🤝 Contributing

When implementing this feature:
1. Follow existing Hashcat coding conventions
2. Test thoroughly with known vectors
3. Validate performance expectations
4. Update documentation as needed
5. Submit PR with clear description

## 📞 Support Resources

- **Hashcat Forums:** https://hashcat.net/forum/
- **GitHub Issues:** https://github.com/hashcat/hashcat/issues
- **Wiki:** https://hashcat.net/wiki/
- **This Documentation:** All questions should be answered here first

## 📊 Document Statistics

| Document | Size | Lines | Read Time |
|----------|------|-------|-----------|
| INDEX.md (this) | 11 KB | ~400 | 10 min |
| EXECUTIVE_SUMMARY.md | 13 KB | ~450 | 15 min |
| PRIVKEY_IMPLEMENTATION_ANALYSIS.md | 17 KB | ~600 | 40 min |
| ARCHITECTURE_FLOW.md | 25 KB | ~850 | 30 min |
| IMPLEMENTATION_GUIDE.md | 24 KB | ~800 | 60 min |
| **Total** | **90 KB** | **~3,100** | **~2.5 hours** |

## 🏁 Next Steps

1. **Read EXECUTIVE_SUMMARY.md** to understand feasibility and scope
2. **Choose your role:**
   - 👨‍💼 **Project Manager:** Stop at Executive Summary
   - 🏗️ **Architect:** Read Analysis + Architecture Flow
   - 💻 **Developer:** Follow Implementation Guide
   - 🧪 **Tester:** Focus on test sections
3. **Start implementation** following the guide
4. **Reference other docs** as needed during development

## ✨ Conclusion

This feature is:
- ✅ **Feasible:** All infrastructure exists
- ✅ **Straightforward:** Clear implementation path
- ✅ **Low-risk:** No core changes needed
- ✅ **Well-documented:** 90 KB of comprehensive documentation
- ✅ **Ready to implement:** Code templates provided

**Estimated Total Effort:** 3-5 days (development + testing)

---

**Documentation Version:** 1.0  
**Last Updated:** 2024  
**Status:** Ready for Implementation
