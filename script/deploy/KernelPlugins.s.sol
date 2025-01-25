// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "./DeployKernelLib.sol";

/**
 * @title DeployValidator
 * @dev Deploys the KernelIntentECDSAValidator only, using the library for common logic.
 *
 * Example usage:
 * forge script scripts/deploy/DeployValidator.s.sol \
 *     --rpc-url $RPC_URL \
 *     --broadcast \
 *     --private-key $PRIVATE_KEY \
 *     --etherscan-api-key $ETHERSCAN_KEY \
 *     --verify \
 *     -vvvv
 *
 *  Unknownligly, the executor is not verified on Tenderly v-nets
 *  if so use the following command to verify the executor plugin
 *
 *  forge verify-contract \
 *    --chain-id 8889 \
 *    --compiler-version 0.8.28 \
 *    --optimizer-runs 200 \
 *    <deployed-Executor-address> \
 *    src/KernelIntentExecutor.sol:KernelIntentExecutor \
 *    --etherscan-api-key $TENDERLY_ACCESS_TOKEN \
 *    -vvvvv
 */
contract KernelPlugins is Script {
    // *********************************************

    /* Pick the salt value */

    bytes32 constant SALT = bytes32(keccak256("KERNEL_PLUGINS_V0"));

    // *********************************************

    function run() external {
        vm.startBroadcast();

        // 1. Get init code
        bytes memory validatorInitCode = DeployKernelLib.getValidatorInitCode();
        bytes memory executorInitCode = DeployKernelLib.getExecutorInitCode();

        // 2. Predict address
        address predictedVal = DeployKernelLib.computeCreate2Address(SALT, keccak256(validatorInitCode));
        console2.log("Predicted Validator Address:", predictedVal);

        address predictedExec = DeployKernelLib.computeCreate2Address(SALT, keccak256(executorInitCode));
        console2.log("Predicted Executor Address:", predictedExec);

        // 3. Deploy
        address validator = DeployKernelLib.deployContract(SALT, validatorInitCode);
        console2.log("Deployed Validator Address:", validator);
        require(validator == predictedVal, "Validator address mismatch with prediction");

        address executor = DeployKernelLib.deployContract(SALT, executorInitCode);
        console2.log("Deployed Validator Address:", executor);
        require(executor == predictedExec, "Executor address mismatch with prediction");

        vm.stopBroadcast();
    }
}
