# SPDX-License-Identifier: Apache-2.0
#
# Makefile for tcp-retrans-exporter
#
# Targets:
#   all         – build everything (BPF object + Go binary)
#   bpf         – compile the eBPF C program with clang
#   go          – build the Go exporter binary
#   vmlinux     – generate vmlinux.h from the running kernel's BTF
#   clean       – remove build artefacts
#   help        – print this help

.PHONY: all bpf go vmlinux clean help

# ──────────────────────────────── variables ───────────────────────────────────

# Toolchain
CLANG     ?= clang
LLC       ?= llc
BPFTOOL   ?= bpftool
GO        ?= go

# Architecture used by clang BPF target (leave blank to auto-detect)
ARCH      ?= $(shell uname -m | sed 's/x86_64/x86/' \
                                   | sed 's/aarch64/arm64/' \
                                   | sed 's/ppc64le/powerpc/' \
                                   | sed 's/mips.*/mips/')

# Directories
BPF_SRC   := bpf/tcpretrans.bpf.c
BPF_HDR   := bpf/common.h
BPF_OBJ   := tcpretrans.bpf.o
VMLINUX   := bpf/vmlinux.h
EXPORTER  := tcp-retrans-exporter

# clang flags for BPF compilation
BPF_CFLAGS := \
	-g \
	-O2 \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I bpf \
	-I /usr/include \
	-I /usr/include/$(shell uname -m)-linux-gnu

# Go CGO flags for dynamic linking against the system libbpf
CGO_CFLAGS  := -I/usr/include
CGO_LDFLAGS := -lelf -lz -lbpf

# ────────────────────────────────── targets ────────────────────────────────────

all: bpf go ## Build BPF object and Go binary

bpf: $(BPF_OBJ) ## Compile the eBPF C program

$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR) $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[bpf] compiled $<  →  $@"

go: $(BPF_OBJ) ## Build the Go exporter binary
	CGO_CFLAGS="$(CGO_CFLAGS)" \
	CGO_LDFLAGS="$(CGO_LDFLAGS)" \
	$(GO) build -o $(EXPORTER) ./cmd/exporter/
	@echo "[go]  built ./$(EXPORTER)"

vmlinux: ## Generate vmlinux.h from the running kernel's BTF
	@echo "[vmlinux] generating $(VMLINUX) ..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	@echo "[vmlinux] done"

clean: ## Remove build artefacts
	rm -f $(BPF_OBJ) $(EXPORTER)

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) \
	    | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'
