// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "src/IntentSimpleAccountFactory.sol";
import "src/IntentSimpleAccount.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/Script.sol";

/**
 * @title DeploySimpleAccountTenderly
 * @dev This contract deploys a SimpleAccount and its factory on a blockchain network, specifically for use with Tenderly
 * and verifies the contracts (proxy and implementation).
 *
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

        // Deploy SimpleAccount implementation
        IntentSimpleAccount simpleAccountImpl = new IntentSimpleAccount(IEntryPoint(entryPointAddress));
        console2.log("IntentSimpleAccount implementation deployed at:", address(simpleAccountImpl));

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





