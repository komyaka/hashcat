# Hash Modes 35911 and 35912: Bitcoin and Ethereum Private Key Modes

## Overview

These modules implement direct private key → address checking for Bitcoin and Ethereum, similar to brainflayer's `-t priv` mode.

## Mode 35911: Bitcoin Private Key → P2PKH (compressed)

**Input:** 64 hex characters (32-byte private key)  
**Output:** Bitcoin P2PKH address (compressed, starts with "1")  
**Algorithm:** secp256k1 EC point multiplication → SHA-256 → RIPEMD-160 → Base58Check

### Usage

```bash
# Basic usage
./hashcat -m 35911 -a 0 bitcoin_addresses.txt privkeys.txt --hex-wordlist

# With example files
./hashcat -m 35911 -a 0 example_btc_addresses.txt example_privkeys.txt --hex-wordlist
```

### Test Vector

**Private key:** `0000000000000000000000000000000000000000000000000000000000000001`  
**Expected address:** `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`

## Mode 35912: Ethereum Private Key → Address

**Input:** 64 hex characters (32-byte private key)  
**Output:** Ethereum address (20 bytes, "0x" prefix)  
**Algorithm:** secp256k1 EC point multiplication → Keccak-256[12:] → address

### Usage

```bash
# Basic usage
./hashcat -m 35912 -a 0 ethereum_addresses.txt privkeys.txt --hex-wordlist

# With example files
./hashcat -m 35912 -a 0 example_eth_addresses.txt example_privkeys.txt --hex-wordlist
```

### Test Vector

**Private key:** `0000000000000000000000000000000000000000000000000000000000000001`  
**Expected address:** `0x7e5f4552091a69125d5dfcb7b8c2659029395bdf`

## Private Key Format

Private keys must be exactly 64 hexadecimal characters (32 bytes):
- With `0x` prefix: `0x0000000000000000000000000000000000000000000000000000000000000001`
- Without prefix: `0000000000000000000000000000000000000000000000000000000000000001`

Both uppercase and lowercase hex characters are accepted.

## Performance

Expected performance on modern GPUs (RTX 4090): ~800K-1.2M keys/sec, bottlenecked by secp256k1 elliptic curve point multiplication.

## Files

- `src/modules/module_35911.c` - Bitcoin CPU module
- `src/modules/module_35912.c` - Ethereum CPU module
- `OpenCL/m35911_a{0,1,3}-pure.cl` - Bitcoin GPU kernels
- `OpenCL/m35912_a{0,1,3}-pure.cl` - Ethereum GPU kernels
- `example_btc_addresses.txt` - Example Bitcoin addresses
- `example_eth_addresses.txt` - Example Ethereum addresses
- `example_privkeys.txt` - Example private keys (for testing)
