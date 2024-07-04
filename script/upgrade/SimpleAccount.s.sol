// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../../src/IntentSimpleAccount.sol";

contract UpgradeSimpleAccount is Script {
    address private ENTRYPOINT_ADDRESS;

    string _network;

    function setUp() public {
        _network = vm.envString("NETWORK");
    }

    function run() public {
        // Setup signer
        string memory privateKeyEnv = string(abi.encodePacked(_network, "_PRIVATE_KEY"));
        string memory privateKeyString = vm.envString(privateKeyEnv);
        uint256 signerPrivateKey = vm.parseUint(privateKeyString);
        address signer = vm.addr(signerPrivateKey);
        console2.log("Signer address:", signer);

        // read the enntrypoint address from the environment
        ENTRYPOINT_ADDRESS = vm.envAddress("ENTRYPOINT_ADDRESS");
        console2.log("Entry point address:", ENTRYPOINT_ADDRESS);

        string memory proxyAddressEnv = string(abi.encodePacked(_network, "_PROXY_ADDRESS"));
        address payable proxyAddress = payable(vm.envAddress(proxyAddressEnv));
        console2.log("Proxy address:", proxyAddress);

        string memory networkSaltEnv = string(abi.encodePacked(_network, "_SALT"));
        uint256 networkSalt = vm.envUint(networkSaltEnv);
        console2.log("Network salt:", networkSalt);

        // Start impersonating the deployer account
        console2.log("Network ID:", block.chainid);
        console2.log("Balance of signer in Ether:", _weiToEther(signer.balance), "ETH");
        console2.log("Balance of signer in Gwei:", _weiToGwei(signer.balance), "Gwei");

        console2.log("Owner of SimpleAccount", signer);
        console2.log("msg.sender", msg.sender);
        console2.log("tx.origin", tx.origin);
        address accountOwner = SimpleAccount(proxyAddress).owner();
        console2.log("Account owner:", accountOwner);
        assert(accountOwner == signer);

        vm.startBroadcast(signerPrivateKey);

        SimpleAccount newImplementation = SimpleAccount(payable(0x16c83BBacc3Ec35fD3484F153C965e2978f371f4));
        console2.log("Deployed SimpleAccount implementation at:", address(newImplementation));

        bytes memory data = abi.encodeWithSelector(SimpleAccount.initialize.selector, signer);
        SimpleAccount(proxyAddress).upgradeToAndCall(address(newImplementation), data);
        console2.log(
            "Upgraded SimpleAccount proxy at", proxyAddress, "to new implementation:", address(newImplementation)
        );

        // verify proxy implementation has been upgraded
        SimpleAccount upgradedAccount = SimpleAccount(proxyAddress);

        // calling a function in the new implementation with empty data should have no effect
        upgradedAccount.execValueBatch(new uint256[](0), new address[](0), new bytes[](0));

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
