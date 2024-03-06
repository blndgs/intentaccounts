// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../../src/SimpleAccount.sol";
import "../../src/SimpleAccountV2.sol";

contract UpgradeSimpleAccount is Script {
    address private immutable ENTRYPOINT_ADDRESS;

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

        // read the enntrypoint address from the environment
        ENTRYPOINT_ADDRESS = vm.addr(vm.envString("ENTRYPOINT_ADDRESS"));
        console2.log("Entry point address:", ENTRYPOINT_ADDRESS);

        string memory proxyAddressEnv = string(abi.encodePacked(_network, "_PROXY_ADDRESS"));
        address proxyAddress = vm.addr(vm.envString(proxyAddressEnv));
        console2.log("Proxy address:", proxyAddress);

        string memory networkSaltEnv = string(abi.encodePacked(_network, "_SALT"));
        uint256 networkSalt = vm.envUint(networkSaltEnv);
        console2.log("Network salt:", networkSalt);

        // Start impersonating the deployer account
        console2.log("Network ID:", block.chainid);
        console2.log("Balance of signer in Ether:", _weiToEther(signer.balance), "ETH");
        console2.log("Balance of signer in Gwei:", _weiToGwei(signer.balance), "Gwei");

        console2.log("Owner of SimpleAccount", signer);

        vm.startBroadcast(signerPrivateKey);

        try new SimpleAccountV2(IEntryPoint(ENTRYPOINT_ADDRESS)) returns (SimpleAccountV2 newImplementation) {
            console2.log("Deployed SimpleAccountV2 implementation at:", address(newImplementation));

            bytes memory data = abi.encodeWithSelector(SimpleAccountV2.initialize.selector, signer);
            SimpleAccountV2(proxyAddress).upgradeToAndCall(address(newImplementation), data);
            console2.log("Upgraded SimpleAccount proxy at", proxyAddress, "to new implementation:", address(newImplementation));

            // verify proxy implementation has been upgraded
            SimpleAccountV2 upgradedAccount = SimpleAccountV2(proxyAddress);

            // calling a function in the new implementation with empty data should have no effect
            upgradedAccount.execValueBatch(new uint256[](0), new address[](0), new bytes[](0));
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

        uint256 endGas = gasleft();
        console2.log("Gas used for upgrade: ", startGas - endGas);

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
