// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// import "forge-std/Test.sol";
import "../src/IntentSimpleAccount.sol";
import "../src/IntentSimpleAccountFactory.sol";
import "@account-abstraction/interfaces/IEntryPoint.sol";
import "@account-abstraction/core/EntryPoint.sol";
import "forge-std/interfaces/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./TestSimpleAccountHelper.sol";
import "./TestBytesHelper.sol";

contract SimpleAccountBscTest is Test {
    using Strings for bytes32;
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;
    using TestSimpleAccountHelper for UserOperation;
    using TestBytesHelper for bytes;

    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 public constant CHAIN_ID = 56;
    uint256 bscFork;

    IntentSimpleAccountFactory factory;
    IntentSimpleAccount simpleAccount;
    uint256 salt;
    IEntryPoint public entryPoint;
    address public ownerAddress;
    uint256 public ownerPrivateKey;
    IERC20 public token;

    string network;

    function setUp() public {
        network = "BSC";

        string memory privateKeyEnv = string(abi.encodePacked(network, "_PRIVATE_KEY"));
        string memory privateKeyString = vm.envString(privateKeyEnv);
        ownerPrivateKey = vm.parseUint(privateKeyString);
        ownerAddress = vm.addr(ownerPrivateKey);
        assertEq(ownerAddress, 0x30543aebBB9c91a7929849Dc07114c6E77710462, "Owner address should match");

        // Create BSC Fork instance
        string memory urlEnv = string(abi.encodePacked(network, "_RPC_URL"));
        bscFork = vm.createSelectFork(vm.envString(urlEnv));
        require(CHAIN_ID == block.chainid, "Chain ID should match");

        vm.startPrank(ownerAddress);

        // Deploy the EntryPoint contract or use an existing one
        entryPoint = EntryPoint(payable(ENTRYPOINT_V06));

        salt = 0;

        // Sync the factory with the deployed contract at Mannet
        factory = new IntentSimpleAccountFactory(entryPoint);
        simpleAccount = factory.createAccount(ownerAddress, salt);

        console2.log("SimpleAccount wallet created at:", address(simpleAccount));
    }

    function testXChainValidateSignature() public {
        uint256 SOURCE_CHAIN_ID = 137; // Polygon
        uint256 DEST_CHAIN_ID = 56; // BSC
        address RECIPIENT_SRC = 0xd7b21a844f3a41c91a73d3F87B83fA93bb6cb518;
        address RECIPIENT_DEST = 0xE381bAB2e0C5b678F2FBb8D4b0949e41a6487c8f;

        bytes memory srcIntent = bytes(
            "{\"chainId\":137, \"sender\":\"0x18Dd70639de2ca9146C32f9c84B90A68bBDaAA96\",\"kind\":\"swap\",\"hash\":\"\",\"sellToken\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"buyToken\":\"0xc2132D05D31c914a87C6611C10748AEb04B58e8F\",\"sellAmount\":10,\"buyAmount\":5,\"partiallyFillable\":false,\"status\":\"Received\",\"createdAt\":0,\"expirationAt\":0}"
        );
        UserOperation memory sourceUserOp = createUserOp(address(simpleAccount), srcIntent);

        bytes memory destIntent = bytes(
            "{\"chainId\":56, \"sender\":\"0x18Dd70639de2ca9146C32f9c84B90A68bBDaAA96\",\"kind\":\"swap\",\"hash\":\"\",\"sellToken\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"buyToken\":\"0xc2132D05D31c914a87C6611C10748AEb04B58e8F\",\"sellAmount\":10,\"buyAmount\":5,\"partiallyFillable\":false,\"status\":\"Received\",\"createdAt\":0,\"expirationAt\":0}"
        );
        UserOperation memory destUserOp = createUserOp(address(simpleAccount), destIntent);

        (bytes32 srcHash, bytes32 destHash) =
            xSign(SOURCE_CHAIN_ID, DEST_CHAIN_ID, ownerPrivateKey, sourceUserOp, destUserOp);

        // solve sourceUserOp
        bytes memory xSrcIntent =
            TestSimpleAccountHelper.createCrossChainCallData(uint16(SOURCE_CHAIN_ID), sourceUserOp.callData, destHash);
        sourceUserOp.signature = bytes(abi.encodePacked(sourceUserOp.signature, xSrcIntent));
        sourceUserOp.callData = abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT_SRC, 0.05 ether);

        /**
         * Uncomment only for debugging *****
         */
        // slice post signature to retrieve the x-chain encoded Intent
        // bytes memory sourceSigXChainCalldata = sourceUserOp.signature._slice(65, sourceUserOp.signature.length);
        // XChainLib.OpType opType = XChainLib.identifyUserOpType(sourceSigXChainCalldata);
        // assertEq(uint(opType), uint(XChainLib.OpType.CrossChain), "OpType should be CrossChain");

        // // extract the source Intent bytes
        // bytes memory extractedIntent = this.extractCallData(sourceSigXChainCalldata);
        // assertEq(extractedIntent, srcIntent, "Source Intent should match");

        // bytes32 srcPostHash = simpleAccount.getUserOpHash(sourceUserOp, SOURCE_CHAIN_ID);
        // assertEq(srcPostHash, srcHash^destHash, "Source Post Hash should match");

        vm.chainId(SOURCE_CHAIN_ID);
        assertEq(SOURCE_CHAIN_ID, block.chainid, "Chain ID should match");
        this.verifySignature(sourceUserOp);

        // solve destUserOp
        bytes memory xDestIntent =
            TestSimpleAccountHelper.createCrossChainCallData(uint16(DEST_CHAIN_ID), destUserOp.callData, srcHash);
        destUserOp.signature = bytes(abi.encodePacked(destUserOp.signature, xDestIntent));
        destUserOp.callData = abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT_DEST, 0.00005 ether);

        vm.chainId(DEST_CHAIN_ID);
        assertEq(DEST_CHAIN_ID, block.chainid, "Chain ID should match");
        this.verifySignature(destUserOp);
    }

    function xSign(
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 privateKey,
        UserOperation memory sourceUserOp,
        UserOperation memory destUserOp
    ) internal view returns (bytes32 hash1, bytes32 hash2) {
        hash1 = simpleAccount.getUserOpHash(sourceUserOp, sourceChainId);
        hash2 = simpleAccount.getUserOpHash(destUserOp, destChainId);

        bytes32 sigHash = hash1 ^ hash2;

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, sigHash.toEthSignedMessageHash());
        bytes memory signature = abi.encodePacked(r, s, v);

        sourceUserOp.signature = signature;
        destUserOp.signature = signature;
    }

    function getUserOpHash(UserOperation calldata userOp, uint256 chainID) public view returns (bytes32) {
        return simpleAccount.getUserOpHash(userOp, chainID);
    }

    function generateSignature(UserOperation memory userOp, uint256 chainID, uint256 prvKey)
        internal
        view
        returns (bytes memory)
    {
        bytes32 userOpHash = simpleAccount.getUserOpHash(userOp, chainID);

        // Sign the hash with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(prvKey, userOpHash.toEthSignedMessageHash());

        // Combine (v, r, s) into a signature
        bytes memory signature = abi.encodePacked(r, s, v);

        return signature;
    }

    function verifySignature(UserOperation calldata userOp) public returns (uint256) {
        uint256 result = simpleAccount.validateSignature(userOp, bytes32(0));
        assertEq(result, 0, "Signature is not valid for the userOp");

        return result;
    }

    function createUserOp(address from, bytes memory callData) internal pure returns (UserOperation memory) {
        UserOperation memory op = UserOperation({
            sender: from,
            nonce: 0,
            initCode: "",
            callData: callData,
            callGasLimit: 100000,
            verificationGasLimit: 100000,
            preVerificationGas: 21000,
            maxFeePerGas: 20 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: "",
            signature: ""
        });

        return op;
    }

    function extractCallData(bytes calldata callData) public pure returns (bytes calldata) {
        return XChainLib.extractCallData(callData);
    }
}
