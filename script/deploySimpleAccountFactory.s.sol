// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Script.sol";
import "../src/SimpleAccountFactory.sol"; // Update with the correct path

contract deploySimpleAccountFactory is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        console.log("Deploying from address:", msg.sender);
        console.log("Network ID:", block.chainid);
        console.log("Balance of Deployer:", address(msg.sender).balance);

        // Define entry point address and owner address
        address entryPointAddress = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
        address eoaOwner = 0xa4BFe126D3aD137F972695dDdb1780a29065e556;

        // Deploy the SimpleAccountFactory with the EntryPoint
        SimpleAccountFactory factory = new SimpleAccountFactory(IEntryPoint(entryPointAddress));
        console.log("SimpleAccountFactory deployed at:", address(factory));

        // Create a unique salt for the account creation
        uint256 salt = 0;

        // Use the factory to create a new SimpleAccount instance
        SimpleAccount account = factory.createAccount(eoaOwner, salt);
        console.log("SimpleAccount created by factory at:", address(account));

        // Optionally, verify the created account's address matches the expected counterfactual address
        address expectedAddress = factory.getAddress(eoaOwner, salt);
        console.log("Expected counterfactual address of created SimpleAccount:", expectedAddress);

        vm.stopBroadcast();
    }
}
