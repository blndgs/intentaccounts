# Intent SimpleAccount & Kernel ERC-4337 Wallets

[![Solidity Tests](https://github.com/blndgs/intentaccounts/actions/workflows/tests.yml/badge.svg)](https://github.com/blndgs/intentaccounts/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/blndgs/intentaccounts/graph/badge.svg?token=VD1LK6PXWT)](https://codecov.io/gh/blndgs/intentaccounts)

This project implements two complementary ERC-4337 compliant smart contract wallets: an enhanced IntentSimpleAccount and a modified ZeroDev Kernel wallet (v2.4). Both implementations support intent-based transactions, with the Kernel integration providing additional modularity through its validator and executor plugins. The project is compatible with EntryPoint v0.6 and supports both same-chain and cross-chain operations through a unified intent handling system.

## Table of Contents
- Project Description
- Key Components
- Installation
- Development Setup
- Testing
- Deployment
- Security
- Contributing
- License

## Project Description
The project offers two distinct but complementary approaches to intent-based account abstraction:

IntentSimpleAccount: An enhanced version of the standard SimpleAccount that adds intent parsing and cross-chain capabilities while maintaining a streamlined architecture.
Kernel Integration: A specialized implementation using ZeroDev's Kernel wallet (v2.4) that leverages the modular validator/executor pattern for maximum flexibility.

Both implementations share these capabilities:
- Same-chain and cross-chain intent processing with unified signatures
- JSON-based intent parsing with transaction bundling
- Full compatibility with EntryPoint v0.6
- Deterministic deployment across networks
- Comprehensive signature validation supporting multiple execution modes
Key features include:
- Cross-chain orchestration through intent correlation and unified signing
- Support for Kernel wallet's validator modes: default, plugin, and sudo
- Flexible execution patterns supporting both direct calls and delegated execution
- Batch transaction execution with native token support
- Intent validation through JSON parsing and cross-chain hash verification
- Upgradeable architecture following OpenZeppelin standards
## Architecture Overview
The project implements two complementary architectures:

IntentSimpleAccount Architecture:
- Direct intent processing with built-in validator
- Streamlined cross-chain coordination
- Minimal proxy pattern for gas-efficient deployment
Kernel Integration Architecture:
- Modular validator/executor pattern
- Support for three validation modes:
* Default mode: Using preset validator
* Plugin mode: Enabling new validators for specific actions
* Sudo mode: Using default plugin for specialized operations
- Extensible execution layer through the KernelIntentExecutor

## Key Components
The project consists of several key smart contracts and libraries:
1. IntentSimpleAccount.sol: Main wallet contract implementing intent-based transaction handling
2. IntentSimpleAccountFactory.sol: Factory contract for deterministic deployment of wallet instances
3. IntentUserOperation.sol: Library for processing intent-based UserOperations
4. KernelIntentValidator.sol: Validator contract for Kernel wallet integration
5. KernelIntentExecutor.sol: Executor handling intent-based transactions in Kernel context
6. xchainlib.sol: Library supporting cross-chain operations
7. CrossChainLib.sol: Core library handling cross-chain message verification and correlation
8. ValidationModes.sol: Implementation of Kernel's flexible validation patterns
9. IntentParser.sol: Library for processing JSON-based intents across chains

## Development Setup
This project uses Git submodules, with a particular requirement around the Kernel wallet integration. The Kernel wallet (v2.4) depends on the ExcessivelySafeCall library, but there's a known configuration issue with how this nested submodule is referenced. To handle this cleanly, we provide a patch script that properly initializes all submodules.
Why is this patch needed?
The Kernel wallet repository contains a nested submodule reference to the ExcessivelySafeCall library. When cloning our project, Git's standard submodule initialization can fail to properly resolve this nested dependency. Our patch script ensures this dependency is correctly initialized without requiring manual intervention.
Follow these steps for proper setup:
1. Initialize the submodules using our patch script:
```bash
chmod +x scripts/patch-kernel-submod.sh
./scripts/patch-kernel-submod.sh
```
2. Install Foundry dependencies:
```bash
forge install
```
The patch script performs the following operations:

Initializes top-level submodules
Properly reinitializes the ExcessivelySafeCall submodule within the Kernel wallet
Ensures all nested dependencies are correctly configured
Sets up the proper Git references for future updates

This initialization process only needs to be done once after cloning the repository. After the initial setup, Git will maintain the correct submodule configuration for all future operations.
Note for CI/CD: Our GitHub workflow includes this patch script in its setup phase, ensuring consistent behavior across local development and automated testing environments.

## Testing
The project includes a comprehensive test suite covering all key components and features. To run the tests, use the following command:
```bash
make test
```

## Deployment
Deployment scripts support both IntentSimpleAccount and Kernel configurations:
1. Set up your environment variables in a .env file:
```bash
<NETWORK>_RPC_URL=<your_rpc_url>
<TEST_PRIVATE_KEY>=<your_private_key>
KERNEL_VERSION=v2.4  # For Kernel deployment
```
2. Deploy using Forge:
Check deployment scripts in the scripts/deploy folder for IntentSimpleAccount and Kernel configurations. You can deploy to any network by setting the appropriate environment variables in your .env file.

## Security
This project is under active development and has not been audited. Use at your own risk in non-production environments only.
## Contributing
Contributions are welcome! Please submit pull requests with tests and documentation updates as appropriate.
## License
This project is licensed under the GPL-3.0 License.