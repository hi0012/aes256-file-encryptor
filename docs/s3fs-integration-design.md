# Design: Transparent AES Encryption for s3fs-fuse

This is the design side of my Operating Systems final project. The aim was to make files stored in Amazon S3 encrypted at rest, while they still look and behave like normal files on the local machine.

## Environment

- Ubuntu Linux (64-bit), kernel 6.x, x86_64
- s3fs-fuse 1.95, compiled from source so I could read, change and debug the code
- FUSE (Filesystem in Userspace)
- OpenSSL libcrypto
- g++ (C++14)

## How the pieces fit

```
Application ──► FUSE (kernel) ──► s3fs ──► Amazon S3
                                   │
                         encrypt on write / decrypt on read
```

Applications use normal Linux system calls. FUSE passes those calls to s3fs, which turns them into S3 API requests. Encryption belongs in the s3fs layer, so neither the application nor FUSE needs to change.

**Write path:** application writes → FUSE forwards the request → s3fs encrypts the data buffer with AES-256-CBC → ciphertext is uploaded to S3.

**Read path:** s3fs downloads the ciphertext from S3 → decrypts the buffer → plaintext goes back through FUSE to the application.

Only file contents are encrypted. File names and metadata are left as they are.

## How I found the right spots in the code

s3fs is a large codebase, so before adding any crypto I wanted to prove where file data actually passes through. I used:

- `grep` / `find` to trace the read and write paths
- An **XOR test**: XOR every byte before upload and reverse it after download. If the file came back intact locally and scrambled in the S3 console, I had the right hooks.
- Running s3fs in the foreground (`-f`) with `printf` tracing to watch the calls happen
- `hexdump` to confirm the `Salted__` header on the stored objects, and `diff` to check decrypted files against the originals

## Status

- ✅ Built s3fs from source and mounted an S3 bucket
- ✅ Traced the upload and download data paths
- ✅ Built and tested the stand-alone AES-256-CBC engine (this repo), compatible with OpenSSL
- ⏳ Final integration into the s3fs source: designed and prototyped, not included in this repo

## What I learned

- How a userspace filesystem sits between the kernel and a cloud API
- Working with buffers in a large C/C++ codebase I didn't write
- Testing to prove each step instead of guessing, which is what the XOR test was for
- The tradeoffs of CBC vs. GCM, and why key derivation matters (see the main README)
