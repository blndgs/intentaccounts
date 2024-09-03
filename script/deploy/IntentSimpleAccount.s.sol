// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "src/IntentSimpleAccountFactory.sol";
import "src/IntentSimpleAccount.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/Script.sol";

/**
 * @title DeploySimpleAccountTenderly
 * @dev This contract deploys a SimpleAccount and its factory
 * and verifies the contracts (proxy and implementation).
 * Make sure you have installed and logged-in to Tenderly CLI if you are deploying at Tenderly.
 *
 * Script arguments:
 * NETWORK=ETHEREUM (.env)
 * ETHEREUM_PRIVATE_KEY (.env)
 *
 * CLI arguments below:
 * export TENDERLY_VERIFIER_URL=https://virtual.mainnet.rpc.tenderly.co/c5ed9a3b-7ad5-4d6a-8e4b-76a4b00ba6ea/verify/etherscan
 * RPC_URL=https://virtual.mainnet.rpc.tenderly.co/c5ed9a3b-7ad5-4d6a-8e4b-76a4b00ba6ea
 * PRIVATE_KEY=
 * TENDERLY_ACCESS_TOKEN=
 *
 * forge script script/deploy/IntentSimpleAccount_Tenderly.s.sol \
 *   --rpc-url $RPC_URL \
 *    --broadcast \
 *    --slow \
 *    --private-key $PRIVATE_KEY \
 *    --etherscan-api-key $TENDERLY_ACCESS_TOKEN \
 *    --verify \
 *    --verifier-url $TENDERLY_VERIFIER_URL \
 *    --ffi
 */
contract DeploySimpleAccountTenderly is Script {
    string internal _network;

    function setUp() public {
        _network = vm.envString("NETWORK");
    }

    /**
     * @dev Deploys a SimpleAccount and its factory on a blockchain network.
     * Make sure you have installed and logged-in to Tenderly CLI.
     */
    function run() public {
        address entryPointAddress = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

        string memory privateKeyEnv = string(abi.encodePacked(_network, "_PRIVATE_KEY"));
        string memory privateKeyString = vm.envString(privateKeyEnv);
        uint256 deployerPrivateKey = vm.parseUint(privateKeyString);
        address deployer = vm.addr(deployerPrivateKey);
        console2.log("Deployer address:", deployer);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy IntentSimpleAccountFactory
        IntentSimpleAccountFactory factory = new IntentSimpleAccountFactory(IEntryPoint(entryPointAddress));
        console2.log("IntentSimpleAccountFactory deployed at:", address(factory));

        // Use salt
        string memory saltEnv = string(abi.encodePacked(_network, "_SALT"));
        uint256 salt = vm.envUint(saltEnv);
        console2.log("Salt:", salt);

        // Deploy a IntentSimpleAccount instance using the factory
        address owner = vm.addr(deployerPrivateKey);
        IntentSimpleAccount simpleAccountProxy = factory.createAccount(owner, salt);
        console2.log("IntentSimpleAccount proxy deployed at:", address(simpleAccountProxy));

        vm.stopBroadcast();
    }
}
