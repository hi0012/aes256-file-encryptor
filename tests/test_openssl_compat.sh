#!/usr/bin/env bash
# Checks that aes256_tool and `openssl enc` can decrypt each other's files.
set -u
TOOL=./aes256_tool
KEY="test-passphrase"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
head -c 100000 /dev/urandom > "$TMP/plain.bin"
pass=0; fail=0
check() { if [ "$1" -eq 0 ]; then echo "PASS  $2"; pass=$((pass+1)); else echo "FAIL  $2"; fail=$((fail+1)); fi; }

$TOOL -e -k "$KEY" -in "$TMP/plain.bin" -out "$TMP/a.enc"
openssl enc -d -aes-256-cbc -md sha256 -pass pass:"$KEY" -in "$TMP/a.enc" -out "$TMP/a.dec" 2>/dev/null
cmp -s "$TMP/plain.bin" "$TMP/a.dec"; check $? "tool encrypt -> openssl decrypt"

openssl enc -aes-256-cbc -md sha256 -pass pass:"$KEY" -in "$TMP/plain.bin" -out "$TMP/b.enc" 2>/dev/null
$TOOL -d -k "$KEY" -in "$TMP/b.enc" -out "$TMP/b.dec"
cmp -s "$TMP/plain.bin" "$TMP/b.dec"; check $? "openssl encrypt -> tool decrypt"

$TOOL -e -nosalt -k "$KEY" -in "$TMP/plain.bin" -out "$TMP/c.enc"
$TOOL -d -nosalt -k "$KEY" -in "$TMP/c.enc" -out "$TMP/c.dec"
cmp -s "$TMP/plain.bin" "$TMP/c.dec"; check $? "round trip with -nosalt"

$TOOL -d -k "wrong-key" -in "$TMP/a.enc" -out "$TMP/x.dec" 2>/dev/null
[ $? -ne 0 ]; check $? "wrong passphrase is rejected"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
