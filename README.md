[![Solidity Tests](https://github.com/blndgs/intentaccounts/actions/workflows/tests.yml/badge.svg)](https://github.com/blndgs/intentaccounts/actions/workflows/tests.yml)

# Intents SimpleAccount ERC-4337 Wallet

This project implements a simple ERC-4337 compliant smart contract wallet called SimpleAccount. It provides basic functionality for executing transactions, handling Ether, and managing a single signer that can send requests through an EntryPoint contract.

## Table of Contents

- [Project Description](#project-description)
- [Installation](#installation)
- [Usage](#usage)
- [Building the Project](#building-the-project)
- [Running Tests](#running-tests)
- [Formatting Code](#formatting-code)
- [Running a Local Anvil Node](#running-a-local-anvil-node)
- [SimpleAccount.sol Overview](#simpleaccountsol-overview)

## Project Description

The Intents SimpleAccount ERC-4337 Wallet project aims to provide a minimalistic example of an ERC-4337 compliant smart contract wallet. ERC-4337 introduces a standardized framework for account abstraction, enabling smart contract wallets to have a unified interface and interact with various components such as Bundlers, EntryPoints, and Paymasters.

The SimpleAccount contract demonstrates the basic functionality required for an ERC-4337 compliant wallet, including executing transactions, handling Ether, and managing a single signer.

## Installation

To install and set up the project, follow these steps:

1. Clone the repository:
```bash
git clone https://github.com/your-username/intents-simpleaccount-erc4337-wallet.git
cd intents-simpleaccount-erc4337-wallet
yarn install
```

## Usage
Detailed usage instructions will be provided here.

## Building the Project
To build the project using Forge, run the following command:
```bash
make build
```

## Running Tests
To run the tests with low verbosity, use the following command:
```bash
make test
```

To run the tests with high verbosity and detailed logs, use:
```
make test-logs
```

Formatting Code
To format the Solidity code using forge fmt, run:
```bash
make fmt
```

## SimpleAccount.sol Overview
The SimpleAccount.sol contract is a minimalistic example of an ERC-4337 compliant smart contract wallet. It inherits from BaseAccount and implements the necessary functionality for executing transactions, handling Ether, and managing a single signer.

The contract includes the following key components:

- `execute`: A method to execute arbitrary transactions.
- `validateUserOp`: A method to validate the user operation signature.
For more details on the contract implementation, refer to the SimpleAccount.sol file.
