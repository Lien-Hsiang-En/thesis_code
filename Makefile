CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Wextra

BPF_CFLAGS := -O2 -g -target bpf

all: tc_redirect.bpf.o loader

tc_redirect.bpf.o: src/tc_redirect.bpf.c include/common.h
	$(CLANG) $(BPF_CFLAGS) -Iinclude -c $< -o $@

loader: src/loader.c include/common.h
	$(CC) $(CFLAGS) -Iinclude $< -o $@ -lbpf -lelf -lz

clean:
	rm -f tc_redirect.bpf.o loader

.PHONY: all clean
