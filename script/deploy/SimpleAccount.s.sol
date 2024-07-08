// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "@account-abstraction/samples/SimpleAccountFactory.sol";
import "../ScriptUintHelper.sol";

contract DeploySimpleAccountFactory is Script {
    using ScriptUintHelper for uint256;

    string _network;

    function setUp() public {
        _network = vm.envString("NETWORK");
    }

    function run() public {
        uint256 startGas = gasleft();

        // Setup signer
        string memory privateKeyEnv = string(abi.encodePacked(_network, "_PRIVATE_KEY"));
        string memory privateKeyString = vm.envString(privateKeyEnv);
        uint256 signerPrivateKey = vm.parseUint(privateKeyString);
        address signer = vm.addr(signerPrivateKey);

        // Start impersonating the deployer account
        console2.log("Network ID:", block.chainid);
        console2.log("Balance of signer in Ether:", signer.balance._weiToEther(), "ETH");
        console2.log("Balance of signer in Gwei:", signer.balance._weiToGwei(), "Gwei");

        console2.log("Owner of SimpleAccount", signer);
        console2.log("msg.sender", msg.sender);
        console2.log("tx.origin", tx.origin);

        vm.startBroadcast(signer);

        // Deploy the SimpleAccountFactory with the EntryPoint
        SimpleAccountFactory factory = SimpleAccountFactory(0x793Bf47262290B0d02d4326bFC3654a0358e12De);
        console2.log("SimpleAccountFactory deployed at:", address(factory));
        uint256 endGas = gasleft();
        console2.log("Gas used for Factory deployment: ", startGas - endGas);
        startGas = endGas;

        // Create a unique salt for the account creation
        string memory saltEnv = string(abi.encodePacked(_network, "_SALT"));
        uint256 salt = vm.envUint(saltEnv);
        console2.log("Salt:", salt);

        // Use the factory to create a new SimpleAccount instance
        SimpleAccount account = factory.createAccount(signer, salt);
        console2.log("SimpleAccount wallet created at:", address(account));
        endGas = gasleft();
        console2.log("Gas used for wallet creation: ", startGas - endGas);
        startGas = endGas;

        // verify the created account's address matches the expected counterfactual address
        address expectedAddress = factory.getAddress(signer, salt);
        assert(address(account) == expectedAddress);
        console2.log("New simpleAccount address:", expectedAddress);
        uint256 nonce = account.getNonce();
        console2.log("Account nonce", nonce);

        vm.stopBroadcast(); // End the broadcast session

        console2.log("Balance of signer in Gwei:", signer.balance._weiToGwei(), "Gwei");
    }
}
