// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "../src/IntentSimpleAccount.sol";
import "../src/IntentSimpleAccountFactory.sol";
import "../src/xchainlib.sol";
import "@account-abstraction/interfaces/IEntryPoint.sol";
import "@account-abstraction/core/EntryPoint.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./TestSimpleAccountHelper.sol";

contract AccountXChainTest is Test {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;

    uint256 public constant SOURCE_CHAIN_ID = 137; // Polygon
    uint256 public constant DEST_CHAIN_ID = 56; // BSC

    IEntryPoint public entryPoint;
    IntentSimpleAccountFactory public factory;
    IntentSimpleAccount public simpleAccount;
    address public ownerAddress;
    uint256 public ownerPrivateKey;

    function setUp() public {
        // Set up owner account
        ownerPrivateKey = uint256(keccak256("owner private key"));
        ownerAddress = vm.addr(ownerPrivateKey);

        // Deploy EntryPoint and SimpleAccountFactory
        entryPoint = new EntryPoint();
        factory = new IntentSimpleAccountFactory(entryPoint);
        simpleAccount = factory.createAccount(ownerAddress, 0);

        // Fund the account with some Ether
        vm.deal(address(simpleAccount), 1 ether);
    }

    function testExecValueBatchWithCrossChainFirst() public {
        // Create call data for a simple transfer
        address recipient1 = address(0xdeadbeef);
        uint256 amount1 = 0.05 ether;
        bytes memory transferCallData1 = abi.encodeWithSignature("transfer(address,uint256)", recipient1, amount1);

        // Compute otherChainHash (for simplicity, use a dummy hash)
        bytes32 otherChainHash = keccak256("dummy other chain hash");

        // Create cross-chain call data for the first function
        bytes memory crossChainCallData =
            TestSimpleAccountHelper.createCrossChainCallData(transferCallData1, otherChainHash);

        // Create a UserOperation
        UserOperation memory userOp = UserOperation({
            sender: address(simpleAccount),
            nonce: simpleAccount.getNonce(),
            initCode: "",
            callData: crossChainCallData,
            callGasLimit: 200000,
            verificationGasLimit: 100000,
            preVerificationGas: 21000,
            maxFeePerGas: 20 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature for the UserOperation
        userOp.signature = generateSignature(userOp, block.chainid);

        // Validate the signature
        uint256 validationResult = simpleAccount.validateSignature(userOp, bytes32(0));
        assertEq(validationResult, 0, "Signature validation failed");

        XChainLib.OpType opType = this.identifyUserOpType(userOp.callData);
        assertEq(uint256(opType), uint256(XChainLib.OpType.CrossChain), "OpType is not CrossChain");

        bytes memory cd = this.extractCallData(userOp.callData);
        assertEq(cd, transferCallData1, "extracted calldata does not match");
    }

    function extractCallData(bytes calldata callData) public pure returns (bytes calldata) {
        return XChainLib.extractCallData(callData);
    }

    function identifyUserOpType(bytes calldata callData) public pure returns (XChainLib.OpType) {
        return XChainLib.identifyUserOpType(callData);
    }

    function generateSignature(UserOperation memory userOp, uint256 chainID) internal view returns (bytes memory) {
        return generateSignature(userOp, chainID, ownerPrivateKey);
    }

    function generateSignature(UserOperation memory userOp, uint256 chainID, uint256 signerPrvKey)
        internal
        view
        returns (bytes memory)
    {
        bytes32 userOpHash = simpleAccount.getUserOpHash(userOp, chainID);

        // Sign the hash with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrvKey, userOpHash.toEthSignedMessageHash());

        // Combine (v, r, s) into a signature
        bytes memory signature = abi.encodePacked(r, s, v);

        return signature;
    }

    function verifySignature(UserOperation memory userOp) internal returns (uint256) {
        // not supplying the userOpHash as _validateSignature calls for the Intent version
        uint256 result = simpleAccount.validateSignature(userOp, bytes32(0));
        assertEq(result, 0, "Signature is not valid for the userOp");

        return result;
    }
}
