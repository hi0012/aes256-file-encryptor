# AES-256-CBC File Encryptor (C / OpenSSL)

A command-line tool written in C that encrypts and decrypts files with AES-256-CBC using OpenSSL's `libcrypto`. Files it encrypts can be decrypted with the standard `openssl enc` command, and files encrypted with `openssl enc` can be decrypted with this tool.

I built it for my Operating Systems final project (Wayne State University, Fall 2025). The goal of that project was to add transparent encryption to **s3fs-fuse**, the FUSE filesystem that mounts an Amazon S3 bucket as a local folder, so that files are encrypted before they leave the machine. This tool is the encryption engine I wrote and tested for that work. The s3fs integration design is written up in [`docs/s3fs-integration-design.md`](docs/s3fs-integration-design.md).

## Features

- AES-256-CBC encryption and decryption with streaming 4 KB buffers, so large files never have to fit in memory
- Salted mode (default) that writes the OpenSSL `Salted__` header with a random 8-byte salt from `RAND_bytes`
- `-nosalt` mode for deterministic output
- Key and IV derived from a passphrase with `EVP_BytesToKey` (SHA-256), matching `openssl enc -md sha256`
- Fails cleanly on a wrong key or a corrupted file (padding check in `EVP_DecryptFinal_ex`)

## Build

Requires a C compiler and the OpenSSL development headers.

```bash
# Ubuntu / Debian
sudo apt install build-essential libssl-dev

make            # builds ./aes256_tool
make test       # runs the OpenSSL compatibility tests
```

## Usage

```bash
./aes256_tool -e|-d -k <passphrase> -in <input file> -out <output file> [-nosalt]
```

```bash
# Encrypt
./aes256_tool -e -k "my passphrase" -in report.pdf -out report.pdf.enc

# Decrypt
./aes256_tool -d -k "my passphrase" -in report.pdf.enc -out report.pdf

# Decrypt something this tool made, using plain OpenSSL instead
openssl enc -d -aes-256-cbc -md sha256 -pass pass:"my passphrase" -in report.pdf.enc -out report.pdf
```

## File format (salted mode)

```
+-------------+---------------+------------------------------+
| "Salted__"  | 8-byte salt   | AES-256-CBC ciphertext       |
| (8 bytes)   | (random)      | (PKCS#7 padded)              |
+-------------+---------------+------------------------------+
```

This is the same layout `openssl enc` uses, which is what makes the two tools interchangeable.

## Testing

`tests/test_openssl_compat.sh` checks four things against a 100 KB random file:

| Test | Result |
|---|---|
| Encrypt with this tool → decrypt with `openssl enc` | byte-for-byte match |
| Encrypt with `openssl enc` → decrypt with this tool | byte-for-byte match |
| Round trip with `-nosalt` | byte-for-byte match |
| Decrypt with the wrong passphrase | rejected with a non-zero exit code |

## Security notes and next steps

I'm keeping these here on purpose, because knowing a design's limits matters as much as the code:

- **Key derivation.** `EVP_BytesToKey` with one iteration is the legacy OpenSSL scheme. I used it for compatibility with `openssl enc`, but it's fast to brute-force. The next version should use **PBKDF2** (`PKCS5_PBKDF2_HMAC`) with a high iteration count, matching `openssl enc -pbkdf2 -iter`.
- **No integrity check.** CBC mode hides the data but doesn't detect tampering. Moving to **AES-256-GCM**, or adding an HMAC over the ciphertext, would fix that.
- **Passphrase on the command line.** Anything typed there shows up in shell history and `ps`. Reading the key from a file or a prompt is the safer choice.

## Tech

C · OpenSSL (libcrypto EVP API) · Linux · Make · Bash
