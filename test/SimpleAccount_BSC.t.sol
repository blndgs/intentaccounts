// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
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
        console2.log("ChainID:", block.chainid);
        require(CHAIN_ID == block.chainid, "Chain ID should match");

        vm.startPrank(ownerAddress);

        // Deploy the EntryPoint contract or use an existing one
        entryPoint = EntryPoint(payable(ENTRYPOINT_V06));
        console2.log("EntryPoint deployed at:", address(entryPoint));

        salt = 0;

        // Sync the factory with the deployed contract at Mannet
        factory = new IntentSimpleAccountFactory(entryPoint);
        simpleAccount = factory.createAccount(ownerAddress, salt);

        console2.log("SimpleAccount wallet created at:", address(simpleAccount));
    }

    function testXChainValidateSignature() public {
        uint256 SOURCE_CHAIN_ID = 137; // Polygon
        uint256 DEST_CHAIN_ID = 56; // BSC
        address RECIPIENT = 0xd7b21a844f3a41c91a73d3F87B83fA93bb6cb518;

        UserOperation memory sourceUserOp = createTransferUserOp(address(simpleAccount), RECIPIENT, 0.05 ether, 1);
        UserOperation memory destUserOp = createTransferUserOp(address(simpleAccount), RECIPIENT, 0.00005 ether, 2);

        xSign(SOURCE_CHAIN_ID, DEST_CHAIN_ID, ownerPrivateKey, sourceUserOp, destUserOp);
        bool srcValid = verifySourceUserOp(SOURCE_CHAIN_ID, DEST_CHAIN_ID, sourceUserOp, ownerAddress);
        assertEq(srcValid, true, "Source userOp signature should be valid");
        bool destValid = verifyDestUserOp(DEST_CHAIN_ID, destUserOp, ownerAddress);
        assertEq(destValid, true, "Dest userOp signature should be valid");
    }

    function xSign(
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 privateKey,
        UserOperation memory sourceUserOp,
        UserOperation memory destUserOp
    ) internal view {
        // Embed destUserOp within sourceUserOp.callData
        sourceUserOp.callData = embedDestUserOpToSource(uint16(sourceChainId), sourceUserOp.callData, destUserOp);

        bytes32 hash1 = simpleAccount.getUserOpHash(sourceUserOp, sourceChainId);

        // Embed hash1 into destUserOp.callData
        destUserOp.callData = embedHash1ToDestOp(uint16(destChainId), destUserOp.callData, hash1);

        bytes32 hash2 = genHash2(hash1, destUserOp, destChainId);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash2.toEthSignedMessageHash());
        bytes memory signature = abi.encodePacked(r, s, v);

        sourceUserOp.signature = signature;
        destUserOp.signature = signature;
    }

    function embedDestUserOpToSource(uint16 sourceChainId, bytes memory sourceCallData, UserOperation memory destUserOp)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            sourceChainId,
            uint16(sourceCallData.length),
            sourceCallData,
            abi.encode(destUserOp) // Encode the entire destUserOp
        );
    }

    function embedHash1ToDestOp(uint16 destChainId, bytes memory destCallData, bytes32 hash1)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(destChainId, uint16(destCallData.length), destCallData, hash1);
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

    function verifySourceUserOp(
        uint256 sourceChainId,
        uint256 destChainId,
        UserOperation memory srcUserOp,
        address signer
    ) internal returns (bool) {
        bytes32 hash1 = simpleAccount.getUserOpHash(srcUserOp, sourceChainId);
        UserOperation memory embeddedDestUserOp = extractDestUserOp(srcUserOp);

        embeddedDestUserOp.callData = embedHash1ToDestOp(uint16(destChainId), embeddedDestUserOp.callData, hash1);
        bytes32 hash2 = genHash2(hash1, embeddedDestUserOp, destChainId);
        bytes32 prefixedHash = hash2.toEthSignedMessageHash();

        bytes memory signature65 = srcUserOp.signature;
        assertEq(signature65.length, 65, "Invalid signature length");

        return signer == prefixedHash.recover(signature65);
    }

    function verifyDestUserOp(uint256 destChainId, UserOperation memory destUserOp, address signer)
        internal
        returns (bool)
    {
        bytes32 hash1 = extractHash1(destUserOp.callData);
        bytes32 hash2 = genHash2(hash1, destUserOp, destChainId);

        bytes32 prefixedHash = hash2.toEthSignedMessageHash();

        bytes memory signature65 = destUserOp.signature;
        assertEq(signature65.length, 65, "Invalid signature length");

        return signer == prefixedHash.recover(signature65);
    }

    function extractDestUserOp(UserOperation memory srcUserOp)
        internal
        pure
        returns (UserOperation memory destUserOp)
    {
        // Skip source chain ID (2 bytes) and source calldata length (2 bytes)
        uint256 destUserOpStart = 4 + uint16(bytes2(srcUserOp.callData._slice(2, 4)));
        bytes memory destUserOpData = srcUserOp.callData._slice(destUserOpStart, srcUserOp.callData.length);

        // Decode the destUserOp data
        destUserOp = abi.decode(destUserOpData, (UserOperation));
    }

    function extractHash1(bytes memory callData) internal pure returns (bytes32 hash1) {
        require(callData.length >= 36, "Invalid callData length"); // 2 (chainId) + 2 (length) + min 1 (data) + 32 (hash1)

        uint16 destCallDataLen;
        assembly {
            destCallDataLen := shr(240, mload(add(callData, 34)))
        }

        require(callData.length == 36 + destCallDataLen, "Invalid callData length");

        assembly {
            hash1 := mload(add(callData, add(36, destCallDataLen)))
        }
    }

    function verifySignature(UserOperation memory userOp) internal returns (uint256) {
        uint256 result = simpleAccount.validateSignature(userOp, bytes32(0));
        assertEq(result, 0, "Signature is not valid for the userOp");

        return result;
    }

    function genHash2(bytes32 hash1, UserOperation memory destUserOp, uint256 chainId)
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(hash1, simpleAccount.getUserOpHash(destUserOp, chainId)));
    }

    function createTransferUserOp(address from, address to, uint256 amount, uint8 opType)
        internal
        pure
        returns (UserOperation memory)
    {
        bytes memory transferData = abi.encodeWithSignature("transfer(address,uint256)", to, amount);

        return UserOperation({
            sender: from,
            nonce: 0,
            initCode: "",
            callData: transferData,
            callGasLimit: 100000,
            verificationGasLimit: 100000,
            preVerificationGas: 21000,
            maxFeePerGas: 20 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: "",
            signature: abi.encodePacked(opType)
        });
    }

    // Original function from the SimpleAccount contract
    function getUserOpHash(UserOperation calldata userOp, uint256 chainID) public pure returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), ENTRYPOINT_V06, chainID));
    }

    // Wrapper around the original function to create a call context
    function getOrigUserOpHash(UserOperation memory userOp, uint256 chainID) internal view returns (bytes32) {
        return this.getUserOpHash(userOp, chainID);
    }

    function generateCallData() internal pure returns (bytes memory) {
        bytes memory fixedCallData =
            hex"b61d27f60000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a76000000000000000000000000000000000000000000000000000000000000037800000000000000000000000000000000000000000000000000000000";

        return fixedCallData;
    }
}
