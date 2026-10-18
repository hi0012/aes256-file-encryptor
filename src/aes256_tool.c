// aes256_tool.c - stand-alone AES-256-CBC file encryption utility (OpenSSL-compatible)
// Author: Hisham Issa

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int issa_enc = 0;
int issa_dec = 0;
int issa_use_salt = 1;

char *issa_key_str = NULL;
char *issa_in_name = NULL;
char *issa_out_name = NULL;

int argv_cnt = 1;

void issa_help(char **argv)
{
    printf("use: %s -e|-d -k key -in input -out output [-nosalt]\n", argv[0]);
    exit(1);
}

void issa_handle_option(int argc, char **argv)
{
    switch (argv[argv_cnt][0]) {
        case '-':
            if (strcmp(argv[argv_cnt] + 1, "e") == 0) {
                issa_enc = 1;
            }
            else if (strcmp(argv[argv_cnt] + 1, "d") == 0) {
                issa_dec = 1;
            }
            else if (strcmp(argv[argv_cnt] + 1, "k") == 0) {
                argv_cnt++;
                if (argv_cnt == argc)
                    issa_help(argv);
                issa_key_str = argv[argv_cnt];
            }
            else if (strcmp(argv[argv_cnt] + 1, "in") == 0) {
                argv_cnt++;
                if (argv_cnt == argc)
                    issa_help(argv);
                issa_in_name = argv[argv_cnt];
            }
            else if (strcmp(argv[argv_cnt] + 1, "out") == 0) {
                argv_cnt++;
                if (argv_cnt == argc)
                    issa_help(argv);
                issa_out_name = argv[argv_cnt];
            }
            else if (strcmp(argv[argv_cnt] + 1, "nosalt") == 0) {
                issa_use_salt = 0;
            }
            else if (strcmp(argv[argv_cnt] + 1, "help") == 0) {
                issa_help(argv);
            }
            else {
                printf("%s: unknown option\n", argv[argv_cnt]);
                issa_help(argv);
            }
            argv_cnt++;
            break;

        default:
            printf("%s: unknown option\n", argv[argv_cnt]);
            issa_help(argv);
            break;
    }
}

int issa_do_encrypt(FILE *fin, FILE *fout, const char *user_key, int use_salt)
{
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const EVP_MD *md = EVP_sha256();

    unsigned char salt[8];
    unsigned char key[32];
    unsigned char iv[32];

    if (use_salt) {
        if (RAND_bytes(salt, sizeof(salt)) != 1) {
            fprintf(stderr, "RAND_bytes failed\n");
            return -1;
        }
        /* write "Salted__" + salt */
        if (fwrite("Salted__", 1, 8, fout) != 8) {
            fprintf(stderr, "write Salted__ failed\n");
            return -1;
        }
        if (fwrite(salt, 1, 8, fout) != 8) {
            fprintf(stderr, "write salt failed\n");
            return -1;
        }
    }

    unsigned char *salt_ptr = use_salt ? salt : NULL;

    int n = EVP_BytesToKey(cipher, md,
                           salt_ptr,
                           (const unsigned char *)user_key,
                           (int)strlen(user_key),
                           1,
                           key,
                           iv);
    if (n != 32) {
        fprintf(stderr, "EVP_BytesToKey error\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        fprintf(stderr, "EncryptInit failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = (int)fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "EncryptUpdate failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        if (fwrite(outbuf, 1, outlen, fout) != (size_t)outlen) {
            fprintf(stderr, "write failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "EncryptFinal failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (outlen > 0) {
        if (fwrite(outbuf, 1, outlen, fout) != (size_t)outlen) {
            fprintf(stderr, "write final failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int issa_do_decrypt(FILE *fin, FILE *fout, const char *user_key, int use_salt)
{
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const EVP_MD *md = EVP_sha256();

    unsigned char salt[8];
    unsigned char key[32];
    unsigned char iv[32];

    if (use_salt) {
        unsigned char head[16];
        size_t r = fread(head, 1, 16, fin);
        if (r != 16) {
            fprintf(stderr, "read header failed\n");
            return -1;
        }
        if (memcmp(head, "Salted__", 8) != 0) {
            fprintf(stderr, "missing Salted__ header\n");
            return -1;
        }
        memcpy(salt, head + 8, 8);
    }

    unsigned char *salt_ptr = use_salt ? salt : NULL;

    int n = EVP_BytesToKey(cipher, md,
                           salt_ptr,
                           (const unsigned char *)user_key,
                           (int)strlen(user_key),
                           1,
                           key,
                           iv);
    if (n != 32) {
        fprintf(stderr, "EVP_BytesToKey error\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        fprintf(stderr, "DecryptInit failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = (int)fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "DecryptUpdate failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        if (fwrite(outbuf, 1, outlen, fout) != (size_t)outlen) {
            fprintf(stderr, "write failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "DecryptFinal failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (outlen > 0) {
        if (fwrite(outbuf, 1, outlen, fout) != (size_t)outlen) {
            fprintf(stderr, "write final failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 1)
        issa_help(argv);

    while (argv_cnt < argc)
        issa_handle_option(argc, argv);

    if ((issa_enc && issa_dec) || (!issa_enc && !issa_dec)) {
        fprintf(stderr, "need either -e or -d\n");
        issa_help(argv);
    }
    if (!issa_key_str || !issa_in_name || !issa_out_name) {
        fprintf(stderr, "missing -k or -in or -out\n");
        issa_help(argv);
    }

    FILE *fin = fopen(issa_in_name, "rb");
    if (!fin) {
        perror("open input");
        return 1;
    }

    FILE *fout = fopen(issa_out_name, "wb");
    if (!fout) {
        perror("open output");
        fclose(fin);
        return 1;
    }

    int ret;
    if (issa_enc)
        ret = issa_do_encrypt(fin, fout, issa_key_str, issa_use_salt);
    else
        ret = issa_do_decrypt(fin, fout, issa_key_str, issa_use_salt);

    fclose(fin);
    fclose(fout);

    if (ret != 0) {
        fprintf(stderr, "aes operation failed\n");
        return 1;
    }

    return 0;
}

