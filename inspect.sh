#!/bin/bash

# File sizes
echo "==> File sizes"
ls -lh target/debug/beacon target/release/beacon

# Strings
echo "==> Unique strings total"
strings target/release/beacon | sort -u | wc -l
echo "==> Strings count"
strings target/release/beacon | wc -l

strings="glimmer beacon cookie mozilla user-agent localhost encrypt key http server endpoint decrypt cipher"
for string in ${strings};do
  echo "==> Strings: ${string}"
  strings target/release/beacon | grep -i ${string}
done

# File identity
echo "==> File types:"
file target/release/beacon
file target/debug/beacon

# Entropy analysis - high entropy sections suggest encryption/compression
echo "==> Binwalk analysis"
binwalk -E target/release/beacon

# Section headers
echo "==> ELF headers"
readelf -S target/release/beacon | head -30

# Dynamic libraries linked
echo "==> ldd libraries"
ldd target/release/beacon