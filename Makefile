CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
LDLIBS  = -lcrypto

aes256_tool: src/aes256_tool.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

test: aes256_tool
	bash tests/test_openssl_compat.sh

clean:
	rm -f aes256_tool

.PHONY: test clean
