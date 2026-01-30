CLANG := clang
BPFTOOL := bpftool

# Paths
SRC_DIR := src
VMLINUX := $(SRC_DIR)/vmlinux.h

# Compiler flags for BPF
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86

.PHONY: all clean vmlinux

all: $(SRC_DIR)/tc_redirect.bpf.o

# Generate vmlinux.h from running kernel's BTF
vmlinux: $(VMLINUX)

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile BPF program
$(SRC_DIR)/tc_redirect.bpf.o: $(SRC_DIR)/tc_redirect.bpf.c $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(SRC_DIR)/*.o $(SRC_DIR)/vmlinux.h
