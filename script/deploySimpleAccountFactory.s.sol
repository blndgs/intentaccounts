// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Script.sol";
import "../src/SimpleAccountFactory.sol"; // Update with the correct path

contract deploySimpleAccountFactory is Script {
    function setUp() public {}

    function run() public {
        uint256 startGas = gasleft();

        bool dryRun = vm.envBool("DRY_RUN");
        console2.log("Dry run:", dryRun);
        if (dryRun) {
            uint256 fork = vm.createFork(vm.envString("MUMBAI_RPC_URL")); // Fork the Mumbai network
            vm.selectFork(fork);
        }

        // Setup signer
        string memory privateKeyString = vm.envString("MUMBAI_PRIVATE_KEY");
        bytes memory privateKeyBytes = bytes(privateKeyString);
        require(privateKeyBytes.length == 32, "Invalid private key length");

        uint256 privateKey = vm.parseUint(privateKeyString);
        address signer = vm.addr(privateKey);
        vm.startBroadcast(signer);

        console2.log("Deploying from address:", msg.sender);
        console2.log("Network ID:", block.chainid);
        console2.log("Balance of Deployer:", address(msg.sender).balance);
        console2.log("Owner of SimpleAccount", signer);

        // Define entry point address and owner address
        address entryPointAddress = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

        // Deploy the SimpleAccountFactory with the EntryPoint
        SimpleAccountFactory factory = new SimpleAccountFactory(IEntryPoint(entryPointAddress));
        console2.log("SimpleAccountFactory deployed at:", address(factory));
        uint256 endGas = gasleft();
        console2.log("Gas used for Factory deployment: ", startGas - endGas);
        startGas = endGas;

        // Create a unique salt for the account creation
        uint256 salt = vm.envUint("MUMBAI_SALT");
        console2.log("Salt:", salt);

        // Use the factory to create a new SimpleAccount instance
        SimpleAccount account = factory.createAccount(signer, salt);
        endGas = gasleft();
        console2.log("Gas used for account deployment: ", startGas - endGas);
        startGas = endGas;

        // Optionally, verify the created account's address matches the expected counterfactual address
        address expectedAddress = factory.getAddress(signer, salt);
        console2.log("Counterfactual address of SimpleAccount:", expectedAddress);
        console2.log("SimpleAccount created by factory at:", address(account));
        console2.log("Gas used for account getAddress(): ", startGas - endGas);

        vm.stopBroadcast();
    }
}
