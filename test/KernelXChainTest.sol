// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE} from "I4337/artifacts/EntryPoint_0_6.sol";
import {ECDSAValidator, ValidationData} from "../lib/kernel/src/validator/ECDSAValidator.sol";
import {IEntryPoint} from "../lib/kernel/lib/I4337/src/interfaces/IEntryPoint.sol";
import {IKernelValidator} from "../lib/kernel/src/interfaces/IKernelValidator.sol";
import {UserOperation} from "../lib/kernel/lib/I4337/src/interfaces/UserOperation.sol";
import {IKernel} from "../lib/kernel/src/interfaces/IKernel.sol";
import {KernelIntentExecutor} from "../src/KernelIntentExecutor.sol";
import {KernelIntentValidator} from "../src/KernelIntentECDSAValidator.sol";
import {Operation} from "../lib/kernel/src/common/Enums.sol";
import {Kernel} from "../lib/kernel/src/Kernel.sol";
import {KernelFactory} from "../lib/kernel/src/factory/KernelFactory.sol";
import {KernelStorage} from "../lib/kernel/src/abstract/KernelStorage.sol";
import {
    KERNEL_STORAGE_SLOT,
    KERNEL_NAME,
    KERNEL_VERSION,
    VALIDATOR_APPROVED_STRUCT_HASH
} from "../lib/kernel/src/common/Constants.sol";
import {ValidAfter, ValidUntil} from "../lib/kernel/src/common/Types.sol";
import {WalletKernelStorage, ExecutionDetail} from "../lib/kernel/src/common/Structs.sol";
import {ECDSA} from "solady/utils/ECDSA.sol"; // used by the plugin
import {EIP712Library} from "./EIP712Library.sol";
import {XChainLib} from "../src/xchainlib.sol";
import "forge-std/Test.sol";

contract KernelXChainTest is Test {
    using ECDSA for bytes32;

    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 constant SOURCE_CHAIN_ID = 137; // Polygon
    uint256 constant DEST_CHAIN_ID = 56; // BSC

    IEntryPoint entryPoint;
    ECDSAValidator defaultValidator;
    KernelIntentValidator intentValidator;
    KernelIntentExecutor intentExecutor;

    address factoryOwnerAddress;
    address ownerAddress;
    uint256 ownerPrivateKey;
    IKernel account;
    KernelFactory factory;
    Kernel kernelImpl;

    function setUp() public {
        // Set up EntryPoint
        entryPoint = IEntryPoint(payable(ENTRYPOINT_V06));
        vm.etch(ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE);
        readEnvVars();

        // Create default ECDSA account
        vm.startPrank(factoryOwnerAddress);
        kernelImpl = new Kernel(entryPoint);
        factory = new KernelFactory(factoryOwnerAddress, entryPoint);
        factory.setImplementation(address(kernelImpl), true);
        defaultValidator = new ECDSAValidator();

        // Plugin setup and intent execution
        defaultValidator = new ECDSAValidator();
        intentExecutor = new KernelIntentExecutor();
        intentValidator = new KernelIntentValidator();

        // Create account with intent validator
        bytes memory initData = abi.encodeWithSelector(
            kernelImpl.initialize.selector,
            intentValidator,
            abi.encodePacked(ownerAddress)
        );
        account = Kernel(payable(address(factory.createAccount(address(kernelImpl), initData, 0))));
        vm.deal(address(account), 1e30);

        // Enable validator
        intentValidator.enable(abi.encodePacked(ownerAddress));
    }

    function readEnvVars() public {
        string memory privateKeyString = vm.envString("ETHEREUM_PRIVATE_KEY");
        console2.log("privateKeyString:", privateKeyString);

        string memory factoryOwnerPrvKeyString = vm.envString("ETHEREUM_KERNEL_FACTORY_OWNER_PRIVATE_KEY");
        factoryOwnerAddress = vm.addr(vm.parseUint(factoryOwnerPrvKeyString));

        // Derive the Ethereum address from the private key
        ownerPrivateKey = vm.parseUint(privateKeyString);
        ownerAddress = vm.addr(ownerPrivateKey);

        console2.log("Owner address:", ownerAddress);

        assertFalse(ownerAddress == address(0), "Owner address should not be the zero address");
    }

    function testKernelCrossChainValidationBasic() public {
        address RECIPIENT_SRC = 0xd7b21a844f3a41c91a73d3F87B83fA93bb6cb518;
        address RECIPIENT_DEST = 0xE381bAB2e0C5b678F2FBb8D4b0949e41a6487c8f;

        // Create source and destination intents
        bytes memory srcIntent = createIntent();
        bytes memory destIntent = createIntent();

        // Create UserOperations
        UserOperation memory srcUserOp = createUserOp(
            address(account),
            srcIntent
        );
        UserOperation memory destUserOp = createUserOp(
            address(account),
            destIntent
        );

        // Compute hashes
        bytes32 srcHash = intentValidator.getUserOpHash(srcUserOp, SOURCE_CHAIN_ID);
        console2.log("srcHash:");
        console2.logBytes32(srcHash);
        bytes32 destHash = intentValidator.getUserOpHash(destUserOp, DEST_CHAIN_ID);
        console2.log("destHash:");
        console2.logBytes32(destHash);

        // UI signs the source and destination userOps
        // xSign(hash1, hash2, ownerPrivateKey, sourceUserOp, destUserOp);
        xSignCommon(srcHash, destHash, ownerPrivateKey, srcUserOp, destUserOp, false);

        // Submit to the bundler
        // Bundler to the solver
        // solve sourceUserOp

        // solve sourceUserOp which means the source userOp receives the EVM calldata solution
        // after appending the cross-chain calldata value (Intent) to the signature
        srcUserOp.signature = bytes(abi.encodePacked(srcUserOp.signature, srcUserOp.callData));
        srcUserOp.callData = abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT_SRC, 0.05 ether);

        // solve destUserOp: the source userOp receives the EVM calldata solution
        // after appending the cross-chain calldata value (Intent) to the signature
        destUserOp.signature = bytes(abi.encodePacked(destUserOp.signature, destUserOp.callData));
        destUserOp.callData = abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT_DEST, 0.00005 ether);

        // Verify signatures on both chains
        vm.chainId(SOURCE_CHAIN_ID);
        assertEq(SOURCE_CHAIN_ID, block.chainid, "Chain ID should match");

        ValidationData srcResult = intentValidator.validateUserOp(srcUserOp, bytes32(0), 0);
        assertEq(ValidationData.unwrap(srcResult), 0, "Source chain validation failed");

        vm.chainId(DEST_CHAIN_ID);
        ValidationData destResult = intentValidator.validateUserOp(destUserOp, bytes32(0), 0);
        assertEq(ValidationData.unwrap(destResult), 0, "Destination chain validation failed");
    }

    function testKernelCrossChainValidationWithExecution() public {
        // We'll do the same addresses used in the basic test
        address RECIPIENT_SRC = 0xd7b21a844f3a41c91a73d3F87B83fA93bb6cb518;
        address RECIPIENT_DEST = 0xE381bAB2e0C5b678F2FBb8D4b0949e41a6487c8f;

        // 1. Create source/dest intents
        bytes memory srcIntent = createIntent();
        bytes memory destIntent = createIntent();

        // 2. Create source/dest userOps
        UserOperation memory srcUserOp = createUserOp(address(account), srcIntent);
        UserOperation memory destUserOp = createUserOp(address(account), destIntent);

        // 3. Compute per-chain hashes
        bytes32 srcHash = intentValidator.getUserOpHash(srcUserOp, SOURCE_CHAIN_ID);
        bytes32 destHash = intentValidator.getUserOpHash(destUserOp, DEST_CHAIN_ID);

        // 4. Cross-chain sign (just like in testKernelCrossChainValidationBasic)
        //    This sets userOp.signature and userOp.callData with XChainLib placeholders
        xSignCommon(srcHash, destHash, ownerPrivateKey, srcUserOp, destUserOp, false);

        // 5. Simulate "solver" step, appending the final solver callData to each signature
        //    (So the cross-chain data parser can read them from `signature[65:]` in `validateUserOp`)
        srcUserOp.signature = abi.encodePacked(srcUserOp.signature, srcUserOp.callData);
        srcUserOp.callData = abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT_SRC, 0.05 ether);

        destUserOp.signature = abi.encodePacked(destUserOp.signature, destUserOp.callData);
        destUserOp.callData = abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT_DEST, 0.00005 ether);

        // 6. Verify signatures on both chains
        vm.chainId(SOURCE_CHAIN_ID);
        assertEq(SOURCE_CHAIN_ID, block.chainid, "Chain ID should match");

        ValidationData srcResult = intentValidator.validateUserOp(srcUserOp, bytes32(0), 0);
        assertEq(ValidationData.unwrap(srcResult), 0, "Source chain validation failed");

        vm.chainId(DEST_CHAIN_ID);
        ValidationData destResult = intentValidator.validateUserOp(destUserOp, bytes32(0), 0);
        assertEq(ValidationData.unwrap(destResult), 0, "Destination chain validation failed");

        // 7. Execute on the source chain
        vm.chainId(SOURCE_CHAIN_ID);
        UserOperation[] memory srcOps = new UserOperation[](1);
        srcOps[0] = srcUserOp;

        // Expect the UserOperationEvent for the source chain
        vm.expectEmit(false, true, true, false);
        emit IEntryPoint.UserOperationEvent(
            0, address(account), address(0), srcUserOp.nonce, true, 0, 0
        );

        entryPoint.handleOps(srcOps, payable(ownerAddress));

        // 8. Execute on the destination chain
        vm.chainId(DEST_CHAIN_ID);
        UserOperation[] memory destOps = new UserOperation[](1);
        destOps[0] = destUserOp;

        // Expect the UserOperationEvent for the destination chain
        vm.expectEmit(false, true, true, false);
        emit IEntryPoint.UserOperationEvent(
            0, address(account), address(0), destUserOp.nonce, true, 0, 0
        );

        entryPoint.handleOps(destOps, payable(ownerAddress));
    }

    function testCrossChainValidationWithInvalidHash() public {
        // Create intents and ops
        bytes memory srcIntent = createIntent();
        bytes memory destIntent = createIntent();

        UserOperation memory srcUserOp = createUserOp(address(account), srcIntent);
        UserOperation memory destUserOp = createUserOp(address(account), destIntent);

        // Generate hashes
        bytes32 srcHash = intentValidator.getUserOpHash(srcUserOp, SOURCE_CHAIN_ID);
        bytes32 destHash = intentValidator.getUserOpHash(destUserOp, DEST_CHAIN_ID);
        bytes32 invalidHash = keccak256("invalid hash");

        // Create invalid hash list (using wrong hash)
        bytes[] memory srcHashList = new bytes[](2);
        srcHashList[0] = abi.encodePacked(uint16(XChainLib.XC_MARKER));
        srcHashList[1] = abi.encodePacked(invalidHash); // Wrong hash

        // Sign with correct hashes
        bytes32 xChainHash = keccak256(abi.encodePacked(srcHash, destHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, xChainHash.toEthSignedMessageHash());
        bytes memory signature = abi.encodePacked(r, s, v);

        // Set up source op with invalid hash list
        srcUserOp.callData = createCrossChainCallData(srcIntent, srcHashList);
        srcUserOp.signature = signature;

        // Validation should fail
        vm.chainId(SOURCE_CHAIN_ID);
        ValidationData result = intentValidator.validateUserOp(srcUserOp, bytes32(0), 0);
        assertTrue(
            ValidationData.unwrap(result) != 0,
            "Validation should fail with invalid hash"
        );
    }

    // Helper functions

    function createIntent() internal pure returns (bytes memory) {
        return bytes(
            '{"fromAsset":{"address":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",'
            '"amount":{"value":"I4byb8EAAA=="},"chainId":{"value":"iQ=="}},'
            '"toStake":{"address":"0x1adB950d8bB3dA4bE104211D5AB038628e477fE6",'
            '"amount":{"value":"D0JA"},"chainId":{"value":"OA=="}}}'
        );
    }

    function createUserOp(
        address sender,
        bytes memory callData
    ) internal view returns (UserOperation memory) {
        return UserOperation({
            sender: sender,
            nonce: IKernel(sender).getNonce(),
            initCode: "",
            callData: callData,
            callGasLimit: 800000,
            verificationGasLimit: 500000,
            preVerificationGas: 50000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: "",
            signature: ""
        });
    }

    function _encodeHashList(
        bytes[] memory hashList
    ) internal pure returns (bytes memory) {
        bytes memory encoded;
        for(uint i = 0; i < hashList.length; i++) {
            encoded = abi.encodePacked(encoded, hashList[i]);
        }
        return encoded;
    }

    function xSignCommon(
        bytes32 hash1,
        bytes32 hash2,
        uint256 privateKey,
        UserOperation memory sourceUserOp,
        UserOperation memory destUserOp,
        bool reverseOrder
    ) internal pure {
        bytes32 xChainHash =
            reverseOrder ? keccak256(abi.encodePacked(hash2, hash1)) : keccak256(abi.encodePacked(hash1, hash2));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, xChainHash.toEthSignedMessageHash());
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build the cross-chain calldata values
        bytes memory placeholder = abi.encodePacked(uint16(XChainLib.XC_MARKER));
        bytes[] memory srcHashList = new bytes[](2);
        bytes[] memory destHashList = new bytes[](2);

        if (reverseOrder) {
            srcHashList[0] = abi.encodePacked(hash2);
            srcHashList[1] = placeholder;

            destHashList[0] = placeholder;
            destHashList[1] = abi.encodePacked(hash1);
        } else {
            srcHashList[0] = placeholder;
            srcHashList[1] = abi.encodePacked(hash2);

            destHashList[0] = abi.encodePacked(hash1);
            destHashList[1] = placeholder;
        }

        // Optional: Add assertions or logging if necessary

        // Set the cross-chain calldata value after signing
        sourceUserOp.callData = createCrossChainCallData(sourceUserOp.callData, srcHashList);
        destUserOp.callData = createCrossChainCallData(destUserOp.callData, destHashList);

        sourceUserOp.signature = signature;
        destUserOp.signature = signature;
    }

    /**
     * @notice Creates cross-chain call data according to the linked hash specification.
     * @param intent The call data for the operation.
     * @param hashList The array of hash list entries (including the placeholder).
     * @return bytes The encoded cross-chain call data.
     */
    function createCrossChainCallData(bytes memory intent, bytes[] memory hashList)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory result = abi.encodePacked(
            uint16(XChainLib.XC_MARKER), // Marker (2 bytes)
            uint16(intent.length), // intentLength (2 bytes)
            intent,
            uint8(hashList.length) // hashListLength (1 byte)
        );

        for (uint256 i = 0; i < hashList.length; i++) {
            result = abi.encodePacked(result, hashList[i]);
        }

        return result;
    }
}