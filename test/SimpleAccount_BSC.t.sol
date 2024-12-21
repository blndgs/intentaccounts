// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

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
    uint256 bscFork;

    IntentSimpleAccountFactory factory;
    IntentSimpleAccount simpleAccount;
    uint256 salt;
    IEntryPoint public entryPoint;
    address public ownerAddress;
    uint256 public ownerPrivateKey;
    IERC20 public token;

    function setUp() public {
        string memory privateKeyString = vm.envString("WALLET_OWNER_KEY");
        ownerPrivateKey = vm.parseUint(privateKeyString);
        ownerAddress = vm.addr(ownerPrivateKey);
        console2.log("Owner address:", ownerAddress);

        // Create BSC Fork instance
        string memory urlEnv = string(abi.encodePacked("BSC", "_RPC_URL"));
        bscFork = vm.createSelectFork(vm.envString(urlEnv));
        require(890 == block.chainid || 56 == block.chainid, "Chain ID should match");
        vm.startPrank(ownerAddress);

        // Deploy the EntryPoint contract or use an existing one
        entryPoint = EntryPoint(payable(ENTRYPOINT_V06));

        salt = 0;

        // Sync the factory with the deployed contract at Mainnet
        factory = new IntentSimpleAccountFactory{salt: 0}(entryPoint);
        simpleAccount = factory.createAccount(ownerAddress, salt);

        console2.log("SimpleAccount wallet created at:", address(simpleAccount));
    }

    function debugCrossChainOperation(UserOperation memory sourceUserOp) private {
        // slice post signature to retrieve the x-chain encoded Intent
        bytes memory sourceSigXChainCalldata = sourceUserOp.signature._slice(65, sourceUserOp.signature.length);
        XChainLib.xCallData memory xcd = this.parseXElems(sourceSigXChainCalldata);
        assertEq(uint256(xcd.opType), uint256(XChainLib.OpType.CrossChain), "OpType should be CrossChain");
        // Add more debugging logic here
    }

    function parseXElems(bytes calldata callData) external pure returns (XChainLib.xCallData memory) {
        return XChainLib.parseXElems(callData);
    }

    function createIntent() internal pure returns (bytes memory) {
        return bytes(
            '{"chainId":137, "sender":"0x18Dd70639de2ca9146C32f9c84B90A68bBDaAA96",'
            '"kind":"swap","hash":"","sellToken":"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",'
            '"buyToken":"0xc2132D05D31c914a87C6611C10748AEb04B58e8F","sellAmount":10,'
            '"buyAmount":5,"partiallyFillable":false,"status":"Received",' '"createdAt":0,"expirationAt":0}'
        );
    }

    function createIntent2() internal pure returns (bytes memory) {
        return bytes(
            '{"fromAsset":{"address":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","amount":{"value":"I4byb8EAAA=="},"chainId":{"value":"iQ=="}},"toStake":{"address":"0x1adB950d8bB3dA4bE104211D5AB038628e477fE6","amount":{"value":"D0JA"},"chainId":{"value":"OA=="}}}'
        );
    }

    function testXChainValidateSignature() public {
        uint256 SOURCE_CHAIN_ID = 137; // Polygon
        uint256 DEST_CHAIN_ID = 56; // BSC
        address RECIPIENT_SRC = 0xd7b21a844f3a41c91a73d3F87B83fA93bb6cb518;
        address RECIPIENT_DEST = 0xE381bAB2e0C5b678F2FBb8D4b0949e41a6487c8f;

        // UI Intent creation
        bytes memory srcIntent = createIntent2();

        bytes memory destIntent = createIntent2();
        UserOperation memory sourceUserOp = createUserOp2(address(simpleAccount), srcIntent);
        sourceUserOp.nonce = 9;
        UserOperation memory destUserOp = createUserOp2(address(simpleAccount), destIntent);
        destUserOp.nonce = 0;

        bytes32 hash1 = simpleAccount.getUserOpHash(sourceUserOp, SOURCE_CHAIN_ID);
        bytes32 hash2 = simpleAccount.getUserOpHash(destUserOp, DEST_CHAIN_ID);

        // UI signs the source and destination userOps
        // xSign(hash1, hash2, ownerPrivateKey, sourceUserOp, destUserOp);
        xSignCommon(hash1, hash2, ownerPrivateKey, sourceUserOp, destUserOp, false);

        // Submit to the bundler
        // Bundler to the solver
        // solve sourceUserOp

        // solve sourceUserOp which means the source userOp receives the EVM calldata solution
        // after appending the cross-chain calldata value (Intent) to the signature
        sourceUserOp.signature = bytes(abi.encodePacked(sourceUserOp.signature, sourceUserOp.callData));
        sourceUserOp.callData = abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT_SRC, 0.05 ether);

        // solve destUserOp: the source userOp receives the EVM calldata solution
        // after appending the cross-chain calldata value (Intent) to the signature
        destUserOp.signature = bytes(abi.encodePacked(destUserOp.signature, destUserOp.callData));
        destUserOp.callData = abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT_DEST, 0.00005 ether);

        /**
         * Uncomment for debugging
         * And compile with '--via-ir' flag to avoid stack too deep error
         *
         * debugCrossChainOperation()
         */

        // Bundler submits cross-chain userOps on-chain
        // On-chain signature verification
        vm.chainId(SOURCE_CHAIN_ID);
        assertEq(SOURCE_CHAIN_ID, block.chainid, "Chain ID should match");
        this.verifySignature(sourceUserOp);
        TestSimpleAccountHelper.printUserOperation(sourceUserOp);

        vm.chainId(DEST_CHAIN_ID);
        assertEq(DEST_CHAIN_ID, block.chainid, "Chain ID should match");
        this.verifySignature(destUserOp);
        TestSimpleAccountHelper.printUserOperation(destUserOp);
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
        sourceUserOp.callData = TestSimpleAccountHelper.createCrossChainCallData(sourceUserOp.callData, srcHashList);
        destUserOp.callData = TestSimpleAccountHelper.createCrossChainCallData(destUserOp.callData, destHashList);

        sourceUserOp.signature = signature;
        destUserOp.signature = signature;
    }

    function getUserOpHash(UserOperation calldata userOp, uint256 chainID) public view returns (bytes32) {
        return simpleAccount.getUserOpHash(userOp, chainID);
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

    function createUserOp2(address from, bytes memory callData) internal pure returns (UserOperation memory) {
        UserOperation memory op = UserOperation({
            sender: from,
            nonce: 1,
            initCode: bytes(hex""),
            callData: callData,
            callGasLimit: 800_000,
            verificationGasLimit: 628384,
            preVerificationGas: 626688,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: "",
            signature: ""
        });

        return op;
    }
}
