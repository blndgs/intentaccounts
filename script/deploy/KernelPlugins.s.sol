// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../../src/KernelIntentECDSAValidator.sol";
import "../../src/KernelIntentExecutor.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

/**
 * @title DeployKernelPlugins
 * @dev Deploys KernelIntentValidator and KernelIntentExecutor using CREATE3 for deterministic addresses.
 * This ensures the same addresses across different chains when using the same salt.
 * The contracts will be deployed to addresses that depend only on:
 * 1. The deployer address
 * 2. The salt value
 * This makes cross-chain deployments more predictable and easier to verify.
 *
 * PRIVATE_KEY (.env)
 *
 * export TENDERLY_VERIFIER_URL=
 * RPC_URL=
 * PRIVATE_KEY=
 * TENDERLY_ACCESS_TOKEN=
 *
 * forge script script/deploy/KernelPlugins.s.sol \
 *     --rpc-url $V__RPC_URL \
 *     --broadcast \
 *     --slow \
 *     --private-key $TEST_PRIVATE_KEY \
 *     --etherscan-api-key $TENDERLY_ACCESS_TOKEN \
 *     --verify \
 *     --verifier-url $V__RPC_URL/verify/etherscan \
 *     --ffi
 *     -vvvvv
 */
contract DeployKernelPlugins is Script {
    // Known CREATE2 Factory deployed at same address on all chains
    // Source: https://github.com/Arachnid/deterministic-deployment-proxy
    // lib/forge-std/src/Base.sol:13:5
    // address constant CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    error Create2FactoryNotDeployed();

    /**
     * Set the salt value ***************
     */

    bytes32 constant SALT = bytes32(uint256(4));

    uint256 internal deployerPrivateKey;

    function setUp() public {
        string memory privateKeyEnv = "PRIVATE_KEY";
        string memory privateKeyString = vm.envString(privateKeyEnv);
        deployerPrivateKey = vm.parseUint(privateKeyString);
        address deployer = vm.addr(deployerPrivateKey);
        console2.log("Deployer address:", deployer);
    }

    /**
     * @notice The main function that Foundry calls when invoking `forge script ... --broadcast`.
     */
    function run() external {
        // Ensure CREATE2 factory is deployed
        if (CREATE2_FACTORY.code.length == 0) {
            revert Create2FactoryNotDeployed();
        }

        // Start broadcasting from the EOA so that the ephemeral script contract
        // is now authorized to send on behalf of your private key.
        vm.startBroadcast(deployerPrivateKey);

        // Now that we are broadcasting, `address(this)` is the contract
        // that will make the CREATE2 calls.

        // 1. Compute predicted addresses in this ephemeral environment
        //    because address(this) is the deployer for the create2 calls.
        bytes memory validatorInitCode = getValidatorInitCode();
        bytes memory executorInitCode = getExecutorInitCode();

        // Add logging for init code
        console2.log("Validator init code length:", validatorInitCode.length);
        console2.log("Executor init code length:", executorInitCode.length);

        console2.log("Predicted Validator Address:", vm.computeCreate2Address(SALT, keccak256(validatorInitCode), CREATE2_FACTORY));
        console2.log("Predicted Executor Address:", vm.computeCreate2Address(SALT, keccak256(executorInitCode), CREATE2_FACTORY));

        // 2. Deploy
        address validator = deployContract(SALT, validatorInitCode);
        console2.log("Validator code size:", validator.code.length);

        address executor = deployContract(SALT, executorInitCode);
        console2.log("Executor code size:", executor.code.length);

        console2.log("Actual Validator Address:", validator);
        console2.log("Actual Executor Address:", executor);

        vm.stopBroadcast();
    }

    function deployContract(bytes32 salt, bytes memory initCode) internal returns (address deployed) {
        // The CREATE2 factory expects the salt and initCode to be concatenated
        bytes memory data = abi.encodePacked(salt, initCode);

        // Make the call to the CREATE2 factory
        (bool success, bytes memory returnData) = CREATE2_FACTORY.call(data);
        require(success, "Create2 deployment failed");

        console2.log("returnData:");
        console2.logBytes(returnData);

        // Get the deployed address
        deployed = vm.computeCreate2Address(salt, keccak256(initCode), CREATE2_FACTORY);

        // Verify the contract was actually deployed
        require(deployed.code.length > 0, "No code deployed at target address");

        return deployed;
    }

    /**
     * @dev Returns the initialization code for the KernelIntentValidator contract.
     * This includes both the contract bytecode and constructor parameters.
     */
    function getValidatorInitCode() internal pure returns (bytes memory) {
        return type(KernelIntentValidator).creationCode;
    }

    /**
     * @dev Returns the initialization code for the KernelIntentExecutor contract.
     * This includes both the contract bytecode and constructor parameters.
     */
    function getExecutorInitCode() internal pure returns (bytes memory) {
        return type(KernelIntentExecutor).creationCode;
    }
}
