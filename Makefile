# Makefile

.PHONY: build test test-logs anvil

# Load variables from .env file
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# Commands
fmt:
	forge fmt

# Build the project using Forge
build:
	forge build

# Run tests with low verbosity
test:
	forge test

# Run tests with high verbosity
test-logs:
	forge test -vvvv

# (Foundry local anvil) do in a separate pane or tab
anvil:
	anvil

