#!/bin/bash

# File sizes
echo "==> File sizes"
ls -lh target/debug/beacon target/release/beacon target/x86_64-unknown-linux-gnu/release/beacon

# Strings
echo "==> Unique strings total"
strings target/x86_64-unknown-linux-gnu/release/beacon | sort -u | wc -l
echo "==> Strings count"
strings target/x86_64-unknown-linux-gnu/release/beacon | wc -l

strings="glimmer beacon cookie mozilla user-agent localhost encrypt key http server endpoint decrypt cipher rustc gcc home/ cpuinfo"
for string in ${strings};do
  echo "==> Strings: ${string}"
  strings target/x86_64-unknown-linux-gnu/release/beacon | grep -i ${string}
done

# File identity
echo "==> File types:"
file target/x86_64-unknown-linux-gnu/release/beacon
file target/debug/beacon

# Entropy analysis - high entropy sections suggest encryption/compression
echo "==> Binwalk analysis"
binwalk -E target/x86_64-unknown-linux-gnu/release/beacon

## Section headers
#echo "==> ELF headers"
#readelf -S target/x86_64-unknown-linux-gnu/release/beacon | head -30

echo "==> Dynamic imports"
readelf -p .dynstr target/x86_64-unknown-linux-gnu/release/beacon

echo "==> Sections present"
readelf -S target/x86_64-unknown-linux-gnu/release/beacon | grep -E '^\s+\[' | awk '{print $2, $3, $6}'

# Dynamic libraries linked
echo "==> ldd libraries"
ldd target/x86_64-unknown-linux-gnu/release/beacon
