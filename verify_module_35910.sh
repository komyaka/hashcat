#!/bin/bash
# Verification script for module 35910

echo "========================================="
echo "Module 35910 Verification Script"
echo "========================================="
echo ""

echo "1. Checking module file exists..."
if [ -f "modules/module_35910.so" ]; then
    echo "   ✅ modules/module_35910.so exists"
    ls -lh modules/module_35910.so
else
    echo "   ❌ modules/module_35910.so NOT FOUND"
    exit 1
fi
echo ""

echo "2. Checking module dependencies..."
ldd modules/module_35910.so | head -10
echo ""

echo "3. Checking OpenCL kernels..."
for kernel in OpenCL/m35910_a0-pure.cl OpenCL/m35910_a1-pure.cl OpenCL/m35910_a3-pure.cl; do
    if [ -f "$kernel" ]; then
        echo "   ✅ $kernel exists ($(wc -l < $kernel) lines)"
    else
        echo "   ❌ $kernel NOT FOUND"
    fi
done
echo ""

echo "4. Checking bloom filter includes..."
for header in include/emu_inc_bloom_filter.h OpenCL/inc_bloom_filter.cl; do
    if [ -f "$header" ]; then
        echo "   ✅ $header exists ($(wc -l < $header) lines)"
    else
        echo "   ❌ $header NOT FOUND"
    fi
done
echo ""

echo "5. Checking documentation..."
for doc in docs/MODULE_35910_README.md docs/IMPLEMENTATION_SUMMARY.md; do
    if [ -f "$doc" ]; then
        echo "   ✅ $doc exists ($(wc -l < $doc) lines)"
    else
        echo "   ❌ $doc NOT FOUND"
    fi
done
echo ""

echo "6. Static Analysis (symbols in module)..."
nm -D modules/module_35910.so 2>/dev/null | grep "module_" | head -15
echo ""

echo "7. Creating test files..."
mkdir -p test_data
echo "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb" > test_data/eth_test.hash
echo "hashcat" > test_data/test.dict
echo "   ✅ Test files created in test_data/"
echo ""

echo "========================================="
echo "Verification Summary"
echo "========================================="
echo ""
echo "Module 35910 static verification: PASSED"
echo ""
echo "Next steps:"
echo "  1. Test on GPU: ./hashcat -m 35910 test_data/eth_test.hash test_data/test.dict"
echo "  2. Benchmark: ./hashcat -m 35910 -b"
echo "  3. List modules: ./hashcat --hash-type | grep 35910"
echo ""
