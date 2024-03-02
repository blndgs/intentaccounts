// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../../src/SimpleAccountFactory.sol";

contract DeploySimpleAccountFactory is Script {
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
        console2.log("Balance of signer in Ether:", _weiToEther(signer.balance), "ETH");
        console2.log("Balance of signer in Gwei:", _weiToGwei(signer.balance), "Gwei");

        console2.log("Owner of SimpleAccount", signer);

        vm.startBroadcast(signerPrivateKey);

        // Define entry point address and owner address
        address entryPointAddress = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

        // Deploy the SimpleAccountFactory with the EntryPoint
        try new SimpleAccountFactory(IEntryPoint(entryPointAddress)) returns (SimpleAccountFactory factory) {
            console2.log("SimpleAccountFactory deployed at:", address(factory));
            uint256 endGas = gasleft();
            console2.log("Gas used for Factory deployment: ", startGas - endGas);
            startGas = endGas;

            // Create a unique salt for the account creation
            string memory saltEnv = string(abi.encodePacked(_network, "_SALT"));
            uint256 salt = vm.envUint(saltEnv);
            console2.log("Salt:", salt);

            // Use the factory to create a new SimpleAccount instance
            try factory.createAccount(signer, salt) returns (SimpleAccount account) {
                console2.log("SimpleAccount wallet created at:", address(account));
                endGas = gasleft();
                console2.log("Gas used for wallet creation: ", startGas - endGas);
                startGas = endGas;

                // verify the created account's address matches the expected counterfactual address
                address expectedAddress = factory.getAddress(signer, salt);
                assert(address(account) == expectedAddress);
                console2.log("New simpleAccount address:", expectedAddress);
                uint nonce = account.getNonce();
                console2.log("Account nonce", nonce);

            } catch Error(string memory reason) {
                console2.log("An error occurred when created a wallet:", reason);
            } catch Panic(uint256 errorCode) {
                console2.log("A panic occurred when created a wallet (code", errorCode, ")");
            } catch {
                console2.log("An unexpected error occurred when created a wallet");
            }
        } catch Error(string memory reason) {
            console2.log("An error occurred when deployed the wallet factory:", reason);
        } catch Panic(uint256 errorCode) {
            console2.log("A panic occurred when deployed the wallet factory (code", errorCode, ")");
        } catch {
            console2.log("An unexpected error occurred when deployed the wallet factory");
        }

        vm.stopBroadcast(); // End the broadcast session

        console2.log("Balance of signer in Gwei:", _weiToGwei(signer.balance), "Gwei");
    }

    function _weiToEther(uint256 weiAmount) private pure returns (uint256) {
        return weiAmount / 1 ether;
    }

    function _weiToGwei(uint256 weiAmount) private pure returns (uint256) {
        return weiAmount / 1 gwei;
    }
}
