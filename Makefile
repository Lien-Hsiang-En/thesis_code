CLANG := clang
BPFTOOL := bpftool
CC := gcc

# Paths
SRC_DIR := src
VMLINUX := $(SRC_DIR)/vmlinux.h

# Compiler flags
BPF_CFLAGS := -g -O2 -target bpf
USER_CFLAGS := -g -O2 -Wall
USER_LDFLAGS := -lbpf -lelf -lz

# Targets
BPF_OBJ := $(SRC_DIR)/tc_redirect.bpf.o
BPF_SKEL := $(SRC_DIR)/tc_redirect.skel.h
LOADER := loader

.PHONY: all clean vmlinux

all: $(BPF_OBJ) $(BPF_SKEL)

# Generate vmlinux.h from running kernel's BTF
vmlinux: $(VMLINUX)

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile BPF program
$(BPF_OBJ): $(SRC_DIR)/tc_redirect.bpf.c $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate BPF skeleton header
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Compile userspace loader (for next step)
$(LOADER): $(SRC_DIR)/loader.c $(BPF_SKEL)
	$(CC) $(USER_CFLAGS) -I$(SRC_DIR) $< -o $@ $(USER_LDFLAGS)

clean:
	rm -f $(SRC_DIR)/*.o $(SRC_DIR)/vmlinux.h $(SRC_DIR)/*.skel.h $(LOADER)