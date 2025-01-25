// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../../src/KernelIntentECDSAValidator.sol";
import "../../src/KernelIntentExecutor.sol";

/**
 * @title DeployKernelLib
 * @dev Common library for deploying Kernel plugin contracts via a known CREATE2 factory.
 */
library DeployKernelLib {
    // If you're using the deterministic-deployment-proxy:
    // https://github.com/Arachnid/deterministic-deployment-proxy
    address constant CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    error Create2FactoryNotDeployed();

    /**
     * @dev Deploys a contract using the known CREATE2 factory.
     *      - The factory is assumed to be at CREATE2_FACTORY.
     *      - The contract's salt and initCode are concatenated and
     *        passed to the factory's fallback, which does create2.
     * @param salt   The salt (bytes32) for the create2 call.
     * @param initCode The contract creation code (type(ContractName).creationCode).
     */
    function deployContract(bytes32 salt, bytes memory initCode) internal returns (address deployed) {
        // Check factory code is present
        if (CREATE2_FACTORY.code.length == 0) {
            revert Create2FactoryNotDeployed();
        }

        // Prepare data: the factory expects concatenation of salt + init code
        bytes memory data = abi.encodePacked(salt, initCode);

        // Call the factory
        (bool success,) = CREATE2_FACTORY.call(data);
        require(success, "Create2 deployment failed");

        // The address is deterministically known. You can do either:
        // Option 1: use the returnData if the factory directly returns the address
        // Option 2: compute it yourself
        // We'll compute it ourselves, matching the Foundry approach:
        address predicted = computeCreate2Address(salt, keccak256(initCode));
        require(predicted.code.length > 0, "No code at predicted address");
        return predicted;
    }

    /**
     * @dev Compute the CREATE2 address for the given salt & init code, using our known factory.
     */
    function computeCreate2Address(bytes32 salt, bytes32 initCodeHash) internal pure returns (address) {
        // The standard formula:
        // address = keccak256(0xff, factory, salt, init_code_hash)[12..31]
        // But we can rely on Foundry's `vm.computeCreate2Address(...)` if we had it in a script.
        // For pure solidity approach:
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), CREATE2_FACTORY, salt, initCodeHash));
        return address(uint160(uint256(hash)));
    }

    /**
     * @dev Returns the initialization code for the KernelIntentValidator contract.
     *      This is the contract bytecode + constructor args (if any).
     */
    function getValidatorInitCode() internal pure returns (bytes memory) {
        return type(KernelIntentValidator).creationCode;
    }

    /**
     * @dev Returns the initialization code for the KernelIntentExecutor contract.
     *      This is the contract bytecode + constructor args (if any).
     */
    function getExecutorInitCode() internal pure returns (bytes memory) {
        return type(KernelIntentExecutor).creationCode;
    }
}
