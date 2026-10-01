# VeriLog developer targets. Requires: go, protoc, forge/anvil/cast (Foundry),
# python3 (>=3.10). Go plugins: make tools.

SHELL := /bin/bash
GOBIN_DIR := $(shell go env GOPATH)/bin
tool = $(shell command -v $(1) 2>/dev/null || echo $(2)/$(1))
ABIGEN ?= $(call tool,abigen,$(GOBIN_DIR))
FORGE  ?= $(call tool,forge,$(HOME)/.foundry/bin)
export PATH := $(PATH):$(GOBIN_DIR):$(HOME)/.foundry/bin

PYTHON ?= python3
VENV   := sdk/python/.venv
PROTOC ?= protoc
# Directory containing google/protobuf/timestamp.proto (shipped with protoc).
PROTOC_INCLUDE ?= $(shell dirname $$(dirname $$(command -v $(PROTOC))))/include

.PHONY: all tools venv proto bindings vectors build certs test test-go test-contracts test-python bench e2e clean

all: build test

tools: ## Install protoc plugins and abigen
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/ethereum/go-ethereum/cmd/abigen@latest

venv: ## Create the Python venv with the SDK installed in editable mode
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -q --upgrade pip
	$(VENV)/bin/pip install -q -e 'sdk/python[dev]'

proto: ## Regenerate Go and Python gRPC code from proto/
	$(PROTOC) -I proto -I $(PROTOC_INCLUDE) \
		--plugin=protoc-gen-go=$(GOBIN_DIR)/protoc-gen-go --plugin=protoc-gen-go-grpc=$(GOBIN_DIR)/protoc-gen-go-grpc \
		--go_out=daemon/gen --go_opt=paths=source_relative \
		--go-grpc_out=daemon/gen --go-grpc_opt=paths=source_relative \
		proto/verilog/v1/verilog.proto
	rm -rf $(VENV)/.proto-tmp && mkdir -p $(VENV)/.proto-tmp
	$(VENV)/bin/python -m grpc_tools.protoc -I proto \
		--python_out=$(VENV)/.proto-tmp --pyi_out=$(VENV)/.proto-tmp --grpc_python_out=$(VENV)/.proto-tmp \
		proto/verilog/v1/verilog.proto
	cp $(VENV)/.proto-tmp/verilog/v1/* sdk/python/verilog_sdk/_proto/
	sed -i.bak 's/^from verilog.v1 import verilog_pb2 as/from . import verilog_pb2 as/' sdk/python/verilog_sdk/_proto/verilog_pb2_grpc.py
	rm -rf sdk/python/verilog_sdk/_proto/*.bak $(VENV)/.proto-tmp

bindings: ## Rebuild the contract and regenerate Go bindings
	cd contracts && $(FORGE) build
	jq '.abi' contracts/out/VeriLogRegistry.sol/VeriLogRegistry.json > contracts/out/VeriLogRegistry.abi
	jq -r '.bytecode.object' contracts/out/VeriLogRegistry.sol/VeriLogRegistry.json > contracts/out/VeriLogRegistry.bin
	$(ABIGEN) --abi contracts/out/VeriLogRegistry.abi --bin contracts/out/VeriLogRegistry.bin \
		--pkg registry --type VeriLogRegistry --out daemon/internal/registry/registry.go

vectors: ## Regenerate the cross-implementation golden vectors in testdata/
	cd daemon && go test ./internal/vectors -update

build: ## Build verilogd and verilog-verify into bin/
	cd daemon && go build -o ../bin/ ./cmd/verilogd ./cmd/verilog-verify

# DEV ONLY mTLS certificates (gitignored): CA, server (localhost, 127.0.0.1),
# agent e2e-agent and auditor dev-auditor. Use your own CA or PKI in production.
CERTS_DIR ?= dev-certs
certs: ## Write development-only mTLS certificates into $(CERTS_DIR)/
	cd daemon && go run ./cmd/verilog-devcerts --out ../$(CERTS_DIR) --agent e2e-agent --auditor dev-auditor

test: test-go test-contracts test-python

test-go:
	cd daemon && go vet ./... && go test -race ./...

test-contracts:
	cd contracts && $(FORGE) test

test-python:
	$(VENV)/bin/pytest -q sdk/python

bench:
	cd daemon && go test -run '^$$' -bench . ./internal/merkle ./internal/engine

e2e: ## Full local run against anvil
	./scripts/e2e.sh

clean:
	rm -rf bin contracts/out contracts/cache contracts/broadcast
