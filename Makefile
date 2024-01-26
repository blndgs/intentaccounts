# Makefile

.PHONY: build test-low test-high deploy-anvil deploy-mumbai anvil

# Load variables from .env file
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# Commands

# Build the project using Forge
build:
	forge build

# Run tests with low verbosity
test-low:
	forge test -v

# Run tests with high verbosity
test-high:
	forge test -vvvv

# Deploy to Anvil
deploy-anvil:
	dotenv -f .env run -- bash -c 'forge script script/deploySimpleAccountFactory.s.sol --broadcast --private-key $$DEFAULT_PRIVATE_KEY --fork-url http://localhost:8545'

# Deploy to Polygon Mumbai
deploy-mumbai:
	dotenv -f .env run -- bash -c 'forge script script/deploySimpleAccountFactory.s.sol --broadcast --private-key $$MUMBAI_PRIVATE_KEY --rpc-url $$MUMBAI_RPC_URL --network polygon-mumbai'

# (Foundry local anvil) do in a separate pane or tab
anvil:
	anvil

