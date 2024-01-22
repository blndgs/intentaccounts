// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Script.sol";
import "../src/SimpleAccountFactory.sol";

contract deploySimpleAccountFactory is Script {
    bool dryRun;

    function setUp() public {}

    function run() public {
        uint256 startGas = gasleft();

        dryRun = vm.envBool("DRY_RUN");
        console2.log("Dry run:", dryRun);
        if (dryRun) {
            uint256 fork = vm.createFork(vm.envString("MUMBAI_RPC_URL")); // Fork the Mumbai network
            vm.selectFork(fork);
        }

        // Setup signer
        string memory mumbaiPrivateKeyString = vm.envString("MUMBAI_PRIVATE_KEY");
        uint256 signerPrivateKey = vm.parseUint(mumbaiPrivateKeyString);
        address signer = vm.addr(signerPrivateKey);
        assert(signer == 0xa4BFe126D3aD137F972695dDdb1780a29065e556);

        // Start impersonating the deployer account
        console2.log("Network ID:", block.chainid);
        console2.log("Balance of signer in Ether:", weiToEther(signer.balance), "ETH");
        console2.log("Balance of signer in Gwei:", weiToGwei(signer.balance), "Gwei");

        console2.log("Owner of SimpleAccount", signer);

        if (!dryRun) {
            vm.startBroadcast(signerPrivateKey);
        }

        // Define entry point address and owner address
        address entryPointAddress = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

        // Deploy the SimpleAccountFactory with the EntryPoint
        try new SimpleAccountFactory(IEntryPoint(entryPointAddress)) returns (SimpleAccountFactory factory) {
            console2.log("SimpleAccountFactory deployed at:", address(factory));
            uint256 endGas = gasleft();
            console2.log("Gas used for Factory deployment: ", startGas - endGas);
            startGas = endGas;

            // Create a unique salt for the account creation
            uint256 salt = vm.envUint("MUMBAI_SALT");
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

        if (!dryRun) {
            vm.stopBroadcast(); // End the broadcast session
        }

        console2.log("Balance of signer in Gwei:", weiToGwei(signer.balance), "Gwei");
    }

    function weiToEther(uint256 weiAmount) private pure returns (uint256) {
        return weiAmount / 1 ether;
    }

    function weiToGwei(uint256 weiAmount) private pure returns (uint256) {
        return weiAmount / 1 gwei;
    }
}
