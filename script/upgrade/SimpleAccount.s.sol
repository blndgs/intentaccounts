// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../../src/SimpleAccount.sol";
import "../../src/UUPSProxy.sol";

contract UpgradeSimpleAccount is Script {
    address payable private constant PROXY_ADDRESS = payable(0xc31bE7F83620D7cEF8EdEbEe0f5aF096A7C0b7F4);
    address private constant ENTRY_POINT_ADDRESS = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

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
        console2.log("Signer address:", signer);

        // Start impersonating the deployer account
        console2.log("Network ID:", block.chainid);
        console2.log("Balance of signer in Ether:", _weiToEther(signer.balance), "ETH");
        console2.log("Balance of signer in Gwei:", _weiToGwei(signer.balance), "Gwei");

        console2.log("Owner of SimpleAccount", signer);

        vm.startBroadcast(signerPrivateKey);

        vm.startBroadcast();
        // SimpleAccount newImplementation;
        try new SimpleAccount(IEntryPoint(ENTRY_POINT_ADDRESS)) returns (SimpleAccount newImplementation) {
            console2.log("Deployed new SimpleAccount implementation at:", address(newImplementation));

            // Upgrade the existing proxy to the new implementation
            UUPSProxy accountProxy = UUPSProxy(PROXY_ADDRESS);
            // upgrade the proxy to the new implementation
            accountProxy.upgradeTo(address(newImplementation));
            console2.log("Upgraded SimpleAccount proxy at", PROXY_ADDRESS, "to new implementation:", address(newImplementation));
        } catch Error(string memory reason) {
            console2.log("An error occurred when deployed the wallet factory:", reason);
            revert(reason);
        } catch Panic(uint256 errorCode) {
            console2.log("A panic occurred when deployed the wallet factory (code", errorCode, ")");
            revert("Panic occurred");
        } catch {
            console2.log("An unexpected error occurred when deployed the wallet factory");
            revert("Unexpected error");
        }

        vm.stopBroadcast();

        console2.log("Balance of signer in Ether:", _weiToEther(signer.balance), "ETH");
        console2.log("Balance of signer in Gwei:", _weiToGwei(signer.balance), "Gwei");
    }

    function _weiToEther(uint256 weiAmount) private pure returns (uint256) {
        return weiAmount / 1 ether;
    }

    function _weiToGwei(uint256 weiAmount) private pure returns (uint256) {
        return weiAmount / 1 gwei;
    }
}
