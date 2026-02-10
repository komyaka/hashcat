# Mode 35900 Troubleshooting Checklist

Use this checklist to diagnose segfaults or selftest failures for mode 35900.

## Pre-Flight Checks

### 1. Verify Bug Fix is Applied
```bash
cd /home/runner/work/hashcat/hashcat
git log --oneline -1 src/hashes.c
```
**Expected**: `118bd9d Fix critical bitwise OR bug in hash sorting logic`

**Status**: [ ] ✓ Fix confirmed

---

### 2. Check System Resources

#### Memory (Host RAM)
```bash
free -h
```
**Required**: 
- Minimum: 2 GB free
- Recommended: 4+ GB free
- Worst case (40M unique salts): 24+ GB free

**Status**: [ ] ✓ Sufficient RAM available

#### GPU Memory (VRAM)
```bash
nvidia-smi  # or rocm-smi for AMD
```
**Required**:
- Minimum: 1 GB free
- Recommended: 2+ GB free

**Status**: [ ] ✓ Sufficient GPU VRAM available

#### Disk Space (for hash files)
```bash
df -h .
```
**Required**: ~1-2 GB for 40M address file

**Status**: [ ] ✓ Sufficient disk space

---

### 3. Validate Hash File

#### File Format
```bash
head -5 your_addresses.txt
tail -5 your_addresses.txt
```

**Each line must be**:
- P2PKH: Starts with `1`, 26-35 chars, Base58 (e.g., `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`)
- P2SH: Starts with `3`, ~34 chars, Base58 (e.g., `3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy`)
- Bech32: Starts with `bc1`, 42 chars (P2WPKH only), lowercase (e.g., `bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq`)

**Common Issues**:
- ❌ Mixed case in Bech32 addresses (must be lowercase)
- ❌ P2WSH addresses (62 chars) - NOT SUPPORTED
- ❌ P2TR addresses (`bc1p...`) - NOT SUPPORTED
- ❌ Testnet addresses (`tb1...`, `2...`, `m...`, `n...`) - NOT SUPPORTED
- ❌ Duplicate addresses (will be removed during load, but slow)

**Validation Command**:
```bash
# Check for invalid characters
grep -v '^[13][1-9A-HJ-NP-Za-km-z]\{25,34\}$\|^bc1[a-z0-9]\{39\}$' your_addresses.txt | head -5
```

**Status**: [ ] ✓ All addresses valid

---

### 4. Check Hashcat Build

#### Verify Binary
```bash
./hashcat --version
```
**Expected**: v6.2.0 or later

**Status**: [ ] ✓ Hashcat version confirmed

#### Check for Debug Build (if issues persist)
```bash
ldd ./hashcat | grep -i sanitizer
```
If present: built with ASAN/UBSAN (may show more detailed errors)

**Status**: [ ] Built with sanitizers (optional)

---

## Selftest Diagnostic

### Run Basic Selftest
```bash
./hashcat -t -m 35900
```

**Expected Output**:
```
Self-test hash type 35900: PASSED
```

**If FAILED**, proceed to detailed diagnostics:

---

### Detailed Selftest Debug

#### 1. Run with Maximum Verbosity
```bash
./hashcat -t -m 35900 --debug-mode=4 --debug-file=selftest_debug.log
cat selftest_debug.log
```

**Look for**:
- Kernel compilation errors
- Memory allocation failures
- Assertion failures
- Math errors (ECC point at infinity, mod errors)

**Status**: [ ] Debug log reviewed

---

#### 2. Verify Test Vector Manually

**Test case** (from `src/modules/module_35900.c`):
- Password: `hashcat`
- Expected Address: `1CkwUnESKuVFyn3PVm1fyyMtXx6CT2STg7`

**Manual Verification** (Python):
```python
import hashlib
import ecdsa
import base58

# Step 1: SHA-256(password)
password = b"hashcat"
private_key = hashlib.sha256(password).digest()
print(f"Private key: {private_key.hex()}")

# Step 2: secp256k1 public key
sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
vk = sk.get_verifying_key()
public_key_bytes = b'\x04' + vk.to_string()
print(f"Uncompressed pubkey: {public_key_bytes.hex()}")

# Step 3: Compress public key
x = vk.to_string()[:32]
y = vk.to_string()[32:]
prefix = b'\x02' if y[-1] % 2 == 0 else b'\x03'
compressed_pubkey = prefix + x
print(f"Compressed pubkey: {compressed_pubkey.hex()}")

# Step 4: HASH160 = RIPEMD160(SHA256(pubkey))
sha256_pk = hashlib.sha256(compressed_pubkey).digest()
hash160 = hashlib.new('ripemd160', sha256_pk).digest()
print(f"HASH160: {hash160.hex()}")

# Step 5: Base58Check encoding
version = b'\x00'  # P2PKH
checksum = hashlib.sha256(hashlib.sha256(version + hash160).digest()).digest()[:4]
address = base58.b58encode(version + hash160 + checksum).decode()
print(f"Address: {address}")

# Expected: 1CkwUnESKuVFyn3PVm1fyyMtXx6CT2STg7
```

**Run and Compare**:
```bash
python3 verify_test_vector.py
```

**Status**: [ ] ✓ Test vector matches expected address

---

#### 3. Check GPU Driver

**NVIDIA**:
```bash
nvidia-smi
nvidia-smi -q | grep "Driver Version"
```
**Recommended**: Driver 525.x or newer

**AMD**:
```bash
rocm-smi
rocminfo | grep "Name"
```
**Recommended**: ROCm 5.4 or newer

**Status**: [ ] ✓ GPU driver up-to-date

---

## 40M Hash Load Test

### Phase 1: Small Scale Test (1,000 hashes)
```bash
head -1000 addresses_40m.txt > test_1k.txt
./hashcat -m 35900 test_1k.txt -a 3 ?l?l?l?l --force
```

**Expected**: Loads successfully, cracking attempt runs

**Status**: [ ] ✓ 1K test passed

---

### Phase 2: Medium Scale Test (10,000 hashes)
```bash
head -10000 addresses_40m.txt > test_10k.txt
./hashcat -m 35900 test_10k.txt -a 3 ?l?l?l?l?l --force
```

**Monitor**:
```bash
# In separate terminal
watch -n 1 'free -h | head -3'
```

**Status**: [ ] ✓ 10K test passed

---

### Phase 3: Large Scale Test (100,000 hashes)
```bash
head -100000 addresses_40m.txt > test_100k.txt
time ./hashcat -m 35900 test_100k.txt -a 3 ?l?l?l?l?l?l --force
```

**Note load time**: _______ seconds

**Status**: [ ] ✓ 100K test passed

---

### Phase 4: Full Scale Test (40M hashes)

**Before running**:
1. [ ] Ensure 4+ GB RAM free
2. [ ] Close unnecessary applications
3. [ ] Monitor in separate terminal:
```bash
watch -n 1 'free -h; nvidia-smi | grep MiB'
```

**Run**:
```bash
time ./hashcat -m 35900 addresses_40m.txt -a 3 <attack_params> --force
```

**If segfault occurs**:

1. **Check error message**:
```bash
dmesg | tail -20
```
Look for: "Out of memory", "Killed", "segmentation fault"

2. **Enable core dump**:
```bash
ulimit -c unlimited
./hashcat -m 35900 addresses_40m.txt -a 3 <attack_params> --force
# If crash occurs:
gdb ./hashcat core
(gdb) bt full  # Get backtrace
```

3. **Run with memory limit**:
```bash
# Limit to 20GB
ulimit -v 20971520
./hashcat -m 35900 addresses_40m.txt -a 3 <attack_params> --force
```

**Status**: [ ] ✓ 40M test passed / [ ] ❌ Failed at _______ hashes

---

## Common Issues & Solutions

### Issue 1: "Parser token length exception"
**Cause**: Invalid address format in hash file
**Solution**: 
```bash
# Find invalid lines
grep -n -v '^[13][1-9A-HJ-NP-Za-km-z]\{25,34\}$\|^bc1[a-z0-9]\{39\}$' addresses_40m.txt > invalid_addresses.txt
cat invalid_addresses.txt
```
Remove or fix invalid addresses.

---

### Issue 2: "Insufficient memory"
**Cause**: Not enough RAM
**Solutions**:
1. Reduce hash count
2. Add swap space:
```bash
sudo fallocate -l 32G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```
3. Upgrade RAM

---

### Issue 3: "Kernel build failed"
**Cause**: GPU driver too old or incompatible
**Solutions**:
1. Update GPU drivers
2. Try different device: `--backend-devices 1` (or 2, 3, etc.)
3. Use CPU mode (very slow): `--backend-devices 1 -D 1`

---

### Issue 4: Selftest passes, but 40M fails
**Likely Causes**:
- Memory exhaustion during hash load
- Hash file corruption (bad encoding, invalid UTF-8)
- Filesystem limits (too many open files)

**Solutions**:
```bash
# Increase file descriptor limit
ulimit -n 65536

# Check file encoding
file addresses_40m.txt
# Should be: ASCII text or UTF-8 text

# Validate no binary data
hexdump -C addresses_40m.txt | head -20
# Should only show readable ASCII
```

---

### Issue 5: Slow performance
**Not a bug**, but optimization tips:
- Use wordlist attack (`-a 0`) instead of brute-force (`-a 3`) when possible
- Enable workload tuning: `-w 3` (desktop) or `-w 4` (headless)
- Use hash file on SSD, not HDD
- Deduplicate addresses before running:
```bash
sort -u addresses_40m.txt > addresses_40m_unique.txt
```

---

## Final Verification Checklist

Before reporting an issue, confirm:

- [ ] ✓ Bitwise OR bug fix is applied (commit 118bd9db)
- [ ] ✓ Selftest passes (`./hashcat -t -m 35900`)
- [ ] ✓ Small-scale test passes (1K addresses)
- [ ] ✓ System has sufficient RAM (2+ GB free)
- [ ] ✓ GPU has sufficient VRAM (1+ GB free)
- [ ] ✓ All addresses in hash file are valid format
- [ ] ✓ GPU drivers are up-to-date
- [ ] ✓ No other memory-intensive applications running
- [ ] ✓ Hash file is not corrupted (no binary data, valid encoding)
- [ ] ✓ Filesystem limits are sufficient (`ulimit -n 65536`)
- [ ] Debug log captured (`--debug-mode=4 --debug-file=debug.log`)

**If all checks pass and issue persists**, proceed to report with:
1. Output of `./hashcat --version`
2. Output of `nvidia-smi` or `rocm-smi`
3. Output of `free -h` and `df -h`
4. Contents of `debug.log`
5. Sample of 10 addresses from hash file
6. Exact command line used
7. Complete error message / backtrace

---

**Document Version**: 1.0  
**Last Updated**: 2024-02-10  
**Related Docs**: 
- `DEEP_ANALYSIS_MODE_35900.md` (technical details)
- `ISSUE_SUMMARY_35900.md` (executive summary)
