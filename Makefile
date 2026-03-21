# vigil — eBPF-based runtime security for AI inference workloads
# Requires: clang, llvm, libbpf-dev, linux-headers (Linux only for BPF targets)

BINARY     := vigil
BPF_SRC    := bpf/probe.c bpf/lsm.c
BPF_OBJ    := bpf/vigil.bpf.o
VMLINUX_H  := bpf/vmlinux.h
CLANG      := clang
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

.PHONY: all build bpf test test-unit test-integration clean generate

all: bpf build

## build: compile the vigil Go binary
build:
	go build -o $(BINARY) ./cmd/vigil

## bpf: compile eBPF C programs to object file (Linux only)
bpf: $(VMLINUX_H)
	$(CLANG) \
		-g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I./bpf/headers \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c bpf/probe.c -o bpf/probe.bpf.o
	$(CLANG) \
		-g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I./bpf/headers \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c bpf/lsm.c -o bpf/lsm.bpf.o
	bpftool gen object $(BPF_OBJ) bpf/probe.bpf.o bpf/lsm.bpf.o

## vmlinux.h: generate BTF header from running kernel
$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

## test-unit: run all pure Go unit tests (works on macOS and Linux)
test-unit:
	go test ./internal/... -v -race -count=1

## test-integration: run e2e tests (Linux + root required, builds eBPF first)
test-integration: bpf
	sudo go test -tags integration -v -count=1 ./test/e2e/

## test: run unit tests only (safe on all platforms)
test: test-unit

## clean: remove built artifacts
clean:
	rm -f $(BINARY) bpf/*.o $(VMLINUX_H)

## help: show this help
help:
	@grep -E '^##' Makefile | sed 's/## //'
