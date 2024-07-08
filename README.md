[![Solidity Tests](https://github.com/blndgs/intentaccounts/actions/workflows/tests.yml/badge.svg)](https://github.com/blndgs/intentaccounts/actions/workflows/tests.yml)

# Intent SimpleAccount ERC-4337 Wallet

This project implements an enhanced version of the ERC-4337 compliant smart contract wallet called IntentSimpleAccount. It extends the functionality of the standard SimpleAccount by adding support for intent-based transactions, allowing for more flexible and powerful account abstraction.

## Table of Contents

- [Project Description](#project-description)
- [Key Components](#key-components)
- [Installation](#installation)
- [Usage](#usage)
- [Building the Project](#building-the-project)
- [Running Tests](#running-tests)
- [Deployment](#deployment)

## Project Description

The Intent SimpleAccount ERC-4337 Wallet project aims to provide an advanced implementation of an ERC-4337 compliant smart contract wallet with support for intent-based transactions. It builds upon the standard SimpleAccount implementation, adding features that allow for more complex transaction execution and validation.

Key features include:
- Support for intent-based transactions
- Enhanced signature validation for intents
- Batch execution of transactions
- Upgradeable contract architecture

## Key Components

1. **IntentSimpleAccount.sol**: The main wallet contract that extends SimpleAccount with intent-based functionality.
2. **IntentSimpleAccountFactory.sol**: Factory contract for deploying new IntentSimpleAccount instances.
3. **IntentUserOperation.sol**: Library for handling intent-based UserOperations.
4. **KernelIntentValidator.sol**: A validator contract for the ZeroDev Kernel wallet integration.
5. **KernelIntentExecutor.sol**: An executor contract for handling intent-based transactions in the Kernel wallet context.

## Installation

To install and set up the project, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/blndgs/intentaccounts.git
   cd intentaccounts
   ```
2. Install Foundry if you haven't already:
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
3. Install dependencies:
   ```bash
   forge install
   ```
## Usage
Detailed usage instructions will be provided as the project develops. The main interaction points will be through the IntentSimpleAccount contract and its factory.
Building the Project
To build the project using Forge, run the following command:
```bash
forge build
```
Running Tests
To run the tests, use the following command:
```bash
forge test
```

## Deployment
Deployment scripts are provided in the script directory. To deploy the contracts, you'll need to set up the appropriate environment variables and run the deployment scripts using Forge. For example:

forge script script/deploy/DeploySimpleAccountFactory.s.sol:DeploySimpleAccountFactory --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast

Make sure to replace $RPC_URL and $PRIVATE_KEY with your actual RPC URL and private key.
Security
This project is under active development and has not been audited. Use at your own risk.
Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
License
This project is licensed under the GPL-3.0 License.

This markdown should now be correctly formatted for your README.md file from the 'Usage' section onwards.
