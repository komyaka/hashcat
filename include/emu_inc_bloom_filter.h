/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 * 
 * Bloom Filter implementation for GPU-accelerated address lookup
 * Optimized for cryptocurrency address checking (ETH/BTC)
 */

#ifndef EMU_INC_BLOOM_FILTER_H
#define EMU_INC_BLOOM_FILTER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

// Bloom filter configuration
#define BLOOM_HASH_COUNT 4  // Number of hash functions (k)
#define BLOOM_BITS_PER_ELEMENT 10  // Bits per element for ~1% false positive rate

// Bloom filter structure
typedef struct bloom_filter
{
  uint32_t *bitset;        // Bit array (allocated on host, copied to GPU)
  uint64_t  bitset_size;   // Size in bits
  uint64_t  bitset_bytes;  // Size in bytes
  uint32_t  num_elements;  // Number of elements inserted
  uint32_t  hash_count;    // Number of hash functions (k)
  
} bloom_filter_t;

// MurmurHash3 32-bit variant for bloom filter hashing
static inline uint32_t murmur3_32(const uint8_t *key, size_t len, uint32_t seed)
{
  const uint32_t c1 = 0xcc9e2d51;
  const uint32_t c2 = 0x1b873593;
  const uint32_t r1 = 15;
  const uint32_t r2 = 13;
  const uint32_t m = 5;
  const uint32_t n = 0xe6546b64;
  
  uint32_t hash = seed;
  
  const int nblocks = len / 4;
  const uint32_t *blocks = (const uint32_t *)(key);
  
  for (int i = 0; i < nblocks; i++)
  {
    uint32_t k = blocks[i];
    
    k *= c1;
    k = (k << r1) | (k >> (32 - r1));
    k *= c2;
    
    hash ^= k;
    hash = ((hash << r2) | (hash >> (32 - r2))) * m + n;
  }
  
  const uint8_t *tail = (const uint8_t *)(key + nblocks * 4);
  uint32_t k1 = 0;
  
  switch (len & 3)
  {
    case 3:
      k1 ^= tail[2] << 16;
      // fallthrough
    case 2:
      k1 ^= tail[1] << 8;
      // fallthrough
    case 1:
      k1 ^= tail[0];
      k1 *= c1;
      k1 = (k1 << r1) | (k1 >> (32 - r1));
      k1 *= c2;
      hash ^= k1;
  }
  
  hash ^= len;
  hash ^= (hash >> 16);
  hash *= 0x85ebca6b;
  hash ^= (hash >> 13);
  hash *= 0xc2b2ae35;
  hash ^= (hash >> 16);
  
  return hash;
}

// Initialize bloom filter
static inline int bloom_filter_init(bloom_filter_t *bf, uint32_t expected_elements)
{
  if (bf == NULL || expected_elements == 0)
  {
    return -1;
  }
  
  bf->num_elements = expected_elements;
  bf->hash_count = BLOOM_HASH_COUNT;
  
  // Calculate optimal bit array size: m = -n*ln(p) / (ln(2)^2)
  // For p=0.01 (1% FP rate): m ≈ n * 9.6, we use 10 bits per element
  bf->bitset_size = (uint64_t)expected_elements * BLOOM_BITS_PER_ELEMENT;
  
  // Round up to nearest multiple of 32 (u32 alignment)
  bf->bitset_size = ((bf->bitset_size + 31) / 32) * 32;
  bf->bitset_bytes = bf->bitset_size / 8;
  
  // Allocate and zero the bitset
  bf->bitset = (uint32_t *)calloc(bf->bitset_bytes / sizeof(uint32_t), sizeof(uint32_t));
  
  if (bf->bitset == NULL)
  {
    return -1;
  }
  
  return 0;
}

// Free bloom filter resources
static inline void bloom_filter_free(bloom_filter_t *bf)
{
  if (bf != NULL && bf->bitset != NULL)
  {
    free(bf->bitset);
    bf->bitset = NULL;
  }
}

// Add element to bloom filter (host-side)
static inline void bloom_filter_add(bloom_filter_t *bf, const uint8_t *data, size_t len)
{
  if (bf == NULL || data == NULL || len == 0)
  {
    return;
  }
  
  for (uint32_t i = 0; i < bf->hash_count; i++)
  {
    // Use different seeds for each hash function
    uint32_t hash = murmur3_32(data, len, i);
    uint64_t bit_pos = hash % bf->bitset_size;
    
    // Set bit in bitset
    uint32_t word_idx = bit_pos / 32;
    uint32_t bit_idx = bit_pos % 32;
    
    bf->bitset[word_idx] |= (1u << bit_idx);
  }
}

// Check if element might be in bloom filter (host-side, for testing)
static inline bool bloom_filter_check(const bloom_filter_t *bf, const uint8_t *data, size_t len)
{
  if (bf == NULL || data == NULL || len == 0)
  {
    return false;
  }
  
  for (uint32_t i = 0; i < bf->hash_count; i++)
  {
    uint32_t hash = murmur3_32(data, len, i);
    uint64_t bit_pos = hash % bf->bitset_size;
    
    uint32_t word_idx = bit_pos / 32;
    uint32_t bit_idx = bit_pos % 32;
    
    if ((bf->bitset[word_idx] & (1u << bit_idx)) == 0)
    {
      return false;
    }
  }
  
  return true;
}

#endif // EMU_INC_BLOOM_FILTER_H
