// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {KernelFactory} from "../../lib/kernel/src/factory/KernelFactory.sol";
import {Kernel} from "../../lib/kernel/src/Kernel.sol";
import {IKernelValidator} from "../../lib/kernel/src/interfaces/IKernelValidator.sol";
import {ECDSAValidator} from "../../lib/kernel/src/validator/ECDSAValidator.sol";

/**
 * @title Create a Kernel account with default ECDSA validator
 *
 * Example usage:
 * forge script scripts/deploy/KernelAccount.s.sol \
 *     --rpc-url $RPC_URL \
 *     --broadcast \
 *     --private-key $PRIVATE_KEY \
 *     --etherscan-api-key $ETHERSCAN_KEY \
 *     --verify \
 *     -vvvv
 *
 */
contract KernelAccount is Script {
    function run() external {
        string memory deployerKeyString = vm.envString("TEST_PRIVATE_KEY");
        uint256 deployerPrivateKey = vm.parseUint(deployerKeyString);
        address deployerAddress = vm.addr(deployerPrivateKey);
        console2.log("deployer address:", deployerAddress);

        string memory ownerKeyString = vm.envString("WALLET_OWNER_KEY");
        uint256 ownerPrivateKey = vm.parseUint(ownerKeyString);
        address ownerAddress = vm.addr(ownerPrivateKey);
        console2.log("owner address:", ownerAddress);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Get init code
        // 1) Initialize the factory and kernel
        // at v2.4 known deployed addresses
        KernelFactory factory = KernelFactory(0x5de4839a76cf55d0c90e2061ef4386d962E15ae3);
        Kernel kernelImpl = Kernel(payable (0xd3082872F8B06073A021b4602e022d5A070d7cfC));

        // 2) Default validator ECDSA
        IKernelValidator defaultValidator = ECDSAValidator(0xd9AB5096a832b9ce79914329DAEE236f8Eea0390);

        // 3) Create account with default validator
        bytes memory initData =
            abi.encodeWithSelector(kernelImpl.initialize.selector, defaultValidator, abi.encodePacked(ownerAddress));
        Kernel account = Kernel(payable(address(factory.createAccount(address(kernelImpl), initData, 0))));
        console2.log("Kernel account created at:", address(account));

        vm.stopBroadcast();
    }
}
