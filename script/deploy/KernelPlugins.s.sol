// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../../src/KernelIntentECDSAValidator.sol";
import "../../src/KernelIntentExecutor.sol";

/**
 * @title DeployKernelPlugins
 * @dev This contract deploys KernelIntentValidator and KernelIntentExecutor.
 * Make sure you have installed and logged-in to Tenderly CLI if you are deploying at Tenderly.
 *
 * NETWORK=ETHEREUM (.env)
 * ETHEREUM_PRIVATE_KEY (.env)
 *
 * export TENDERLY_VERIFIER_URL=https://virtual.mainnet.rpc.tenderly.co/c5ed9a3b-7ad5-4d6a-8e4b-76a4b00ba6ea/verify/etherscan
 * RPC_URL=https://virtual.mainnet.rpc.tenderly.co/c5ed9a3b-7ad5-4d6a-8e4b-76a4b00ba6ea
 * PRIVATE_KEY=
 * TENDERLY_ACCESS_TOKEN=
 *
 * forge script script/deploy/KernelPlugins.s.sol \
 *   --rpc-url $RPC_URL \
 *    --broadcast \
 *    --slow \
 *    --private-key $PRIVATE_KEY \
 *    --etherscan-api-key $TENDERLY_ACCESS_TOKEN \
 *    --verify \
 *    --verifier-url $TENDERLY_VERIFIER_URL \
 *    --ffi
 */
contract DeployKernelPlugins is Script {
    string internal _network;
    uint internal deployerPrivateKey;

    function setUp() public {
        _network = vm.envString("NETWORK");

        string memory privateKeyEnv = string(abi.encodePacked(_network, "_PRIVATE_KEY"));
        string memory privateKeyString = vm.envString(privateKeyEnv);
        deployerPrivateKey = vm.parseUint(privateKeyString);
        address deployer = vm.addr(deployerPrivateKey);
        console2.log("Deployer address:", deployer);
    }

    function run() external {
        vm.startBroadcast(deployerPrivateKey);

        // Deploy KernelIntentValidator
        KernelIntentValidator validator = new KernelIntentValidator();
        console.log("KernelIntentValidator deployed at:", address(validator));

        // Deploy KernelIntentExecutor
        KernelIntentExecutor executor = new KernelIntentExecutor();
        console.log("KernelIntentExecutor deployed at:", address(executor));

        vm.stopBroadcast();
    }
}
