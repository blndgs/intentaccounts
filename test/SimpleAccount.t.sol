// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "../src/SimpleAccount.sol";
import "../src/IEntryPoint.sol"; // Ensure this import path is correct
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/EntryPoint.sol";
import "../src/SimpleAccountFactory.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

using Strings for bytes32;
using UserOperationLib for UserOperation;

contract SimpleAccountTest is Test {
    address constant public ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 constant public MUMBAI_CHAIN_ID = 80001;

    using ECDSA for bytes32;

    SimpleAccountFactory public factory;
    IEntryPoint public entryPoint;
    address public ownerAddress;
    uint256 public ownerPrivateKey;

    function setUp() public {
        vm.prank(ownerAddress);

        // Deploy the EntryPoint contract or use an existing one
        entryPoint = new EntryPoint();

        // Retrieve the MUMBAI_PRIVATE_KEY from the .env file
        string memory mumbaiPrivateKeyString = vm.envString(
            "MUMBAI_PRIVATE_KEY"
        );
        console.log("Private Key:", mumbaiPrivateKeyString);

        // Derive the Ethereum address from the private key
        ownerPrivateKey = vm.parseUint(mumbaiPrivateKeyString);
        ownerAddress = vm.addr(ownerPrivateKey);

        // Deploy the SimpleAccountFactory with the entry point
        factory = new SimpleAccountFactory(entryPoint);
    }

    function testValidateSignature() public {
        uint256 salt = 0;
        // Create an account using the factory
        SimpleAccount simpleAccount = factory.createAccount(ownerAddress, salt);

        // Validate the account address
        address expectedAddress = factory.getAddress(ownerAddress, salt);
        assertEq(address(simpleAccount), expectedAddress, "Account address does not match expected address");

        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: ownerAddress,
            nonce: 0,
            initCode: "",
            callData: "",
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: "",
            signature: ""
        });

        // Get the hash of the UserOperation object from the EntryPoint contract
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp); // Modify this line to use entryPoint

        // Sign the hash with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, userOpHash.toEthSignedMessageHash());

        // Combine (v, r, s) into a signature
        bytes memory signature = abi.encodePacked(r, s, v);

        // Update the user operation with the generated signature
        userOp.signature = signature;

        // Test the _validateSignature method
        uint256 result = simpleAccount.ValidateSignature(userOp, userOpHash);
        assertEq(result, 0, "Signature should be valid");
    }

    // Signature Steps:
    // 1. Pack the UserOperation object
    //    function pack(UserOperation calldata userOp) internal pure returns (bytes memory ret) {
    //        address sender = getSender(userOp);
    //        uint256 nonce = userOp.nonce;
    //        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
    //        bytes32 hashCallData = calldataKeccak(userOp.callData);
    //        uint256 callGasLimit = userOp.callGasLimit;
    //        uint256 verificationGasLimit = userOp.verificationGasLimit;
    //        uint256 preVerificationGas = userOp.preVerificationGas;
    //        uint256 maxFeePerGas = userOp.maxFeePerGas;
    //        uint256 maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
    //        bytes32 hashPaymasterAndData = calldataKeccak(userOp.paymasterAndData);
    //
    //        return abi.encode(
    //            sender, nonce,
    //            hashInitCode, hashCallData,
    //            callGasLimit, verificationGasLimit, preVerificationGas,
    //            maxFeePerGas, maxPriorityFeePerGas,
    //            hashPaymasterAndData
    //        );
    //    }
    // 2. Hash the packed UserOperation object
    // return keccak256(pack(userOp));

    // 3. generate a hash Id
    // return keccak256(abi.encode(userOp.hash(), address(EntryPoint), block.chainid));

    // 4. Crete an Ethereum Text Signed Message, from the `hash`
    // ethSigned = userOpHash.toEthSignedMessageHash()
    //    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 message) {
    //        // 32 is the length in bytes of hash,
    //        // enforced by the type signature above
    //        /// @solidity memory-safe-assembly
    //        assembly {
    //            mstore(0x00, "\x19Ethereum Signed Message:\n32")
    //            mstore(0x1c, hash)
    //            message := keccak256(0x00, 0x3c)
    //        }
    //    }

    // 5. Sign the Eth Signed text with the owner's private key
    // vm.sign(ownerPrivateKey, ethSigned)

    function getUserOpHash(
        UserOperation calldata userOp,
        uint256 chainID
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), ENTRYPOINT_V06, chainID));
    }

    function testValidateMumbaiVanillaOp() public {
        vm.chainId(MUMBAI_CHAIN_ID);

        uint256 salt = 0;
        // Create an account using the factory
        SimpleAccount simpleAccount = factory.createAccount(ownerAddress, salt);

        // Validate the account address
        address expectedAddress = factory.getAddress(ownerAddress, salt);
        assertEq(
            address(simpleAccount),
            expectedAddress,
            "Account address does not match expected address"
        );

        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: 0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47,
            nonce: 0x8,
            initCode: bytes(hex""),
            callData: bytes(hex""),
            callGasLimit: 0x2dc6c0,
            verificationGasLimit: 0x2dc6c0,
            preVerificationGas: 0xbb70,
            maxFeePerGas: 0x7e498f31e,
            maxPriorityFeePerGas: 0x7e498f300,
            paymasterAndData: bytes(hex""),
            signature: bytes(
                hex"92f25342760a82b7e5649ed7c6d2d7cb93c0093f66c916d7e57de4af0ae00e2b0524bf364778c6b30c491354be332a1ce521e8a57c5e26f94f8069a404520e931b"
            )
        });

        // Convert the memory object to the calldata object
        bytes memory encodedData = abi.encodeWithSelector(
            this.getUserOpHash.selector,
            userOp,
            block.chainid
        );
        assertEq(block.chainid, MUMBAI_CHAIN_ID, "chainid should be 80001");
        (bool ok, bytes memory hashBytes) = address(this).call(encodedData);
        require(ok, "call failed");
        bytes32 userOpHash = abi.decode(hashBytes, (bytes32));
        logBytes32Value("userOpHash:", userOpHash);

        // Sign the hash with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            ownerPrivateKey,
            userOpHash.toEthSignedMessageHash()
        );

        // Combine (v, r, s) into a signature
        bytes memory signature = abi.encodePacked(r, s, v);

        // Convert the generated signature to a hex string
        string memory generatedSignatureHex = toHexString(signature);

        // Convert the userOp.signature from bytes to a hex string for comparison
        string memory userOpSignatureHex = toHexString(userOp.signature);

        // Print the signatures
        console2.log("Generated Signature:", generatedSignatureHex);
        console2.log("UserOp Signature:", userOpSignatureHex);

        assertEq(generatedSignatureHex, userOpSignatureHex, "Signatures should match");

        uint256 result = simpleAccount.ValidateSignature(userOp, userOpHash);
        assertEq(result, 0, "Signature is not valid for the userOp");
    }

    function hexStringToBytes32(
        string memory hexString
    ) public pure returns (bytes32 result) {
        bytes memory source = bytes(hexString);

        // Ensure the input string is the correct length for a bytes32 type
        require(
            source.length == 66,
            "Hex string must be 66 characters long including '0x'."
        );

        result = 0x0;
        assembly {
            result := mload(add(hexString, 32))
        }
        return result;
    }

    function logBytes32Value(string memory prompt, bytes32 value) public pure {
        // Convert bytes32 to string
        string memory valueAsString = toHexString(abi.encodePacked(value));

        // Log the value
        console2.log(prompt, valueAsString);
    }

    function toHexString(bytes memory b) internal pure returns (string memory) {
        bytes memory hexString = new bytes(2 * b.length + 2);
        hexString[0] = "0";
        hexString[1] = "x";

        for (uint i = 0; i < b.length; i++) {
            uint value = uint8(b[i]);
            uint hi = value / 16;
            uint lo = value - (hi * 16);

            bytes1 hiHexChar = bytes1(uint8(hi < 10 ? hi + 48 : hi + 87));
            bytes1 loHexChar = bytes1(uint8(lo < 10 ? lo + 48 : lo + 87));

            hexString[2 * i + 2] = hiHexChar;
            hexString[2 * i + 3] = loHexChar;
        }

        return string(hexString);
    }

    function testValidateNewSimpleAccountAddress() public {
        // Define a unique salt for each account
        uint256 salt = uint256(keccak256(abi.encodePacked("unique salt")));

        // Create an account using the factory
        SimpleAccount simpleAccount = factory.createAccount(ownerAddress, salt);

        // Validate the account address
        console2.log("SimpleAccount address with salt:", address(simpleAccount));
        address expectedAddress = factory.getAddress(ownerAddress, salt);
        assertEq(address(simpleAccount), expectedAddress, "Account address does not match expected address");

        // Create an account using the factory
        salt = 0;
        simpleAccount = factory.createAccount(ownerAddress, salt);

        // Validate the account address
        console2.log("SimpleAccount address without salt:", address(simpleAccount));
        expectedAddress = factory.getAddress(ownerAddress, salt);
        assertEq(address(simpleAccount), expectedAddress, "Account address does not match expected address");
    }
}
