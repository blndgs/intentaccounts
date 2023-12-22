// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "../src/SimpleAccount.sol";
import "../src/IEntryPoint.sol"; // Ensure this import path is correct
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/EntryPoint.sol";
import "../src/SimpleAccountFactory.sol";

contract SimpleAccountTest is Test {
    using ECDSA for bytes32;

    SimpleAccountFactory public factory;
    IEntryPoint public entryPoint;
    address public ownerAddress;
    uint256 public ownerPrivateKey;

    function setUp() public {
        // Deploy the EntryPoint contract or use an existing one
        entryPoint = new EntryPoint(); // Adjust as needed for your actual EntryPoint deployment

        // Create a private key and corresponding address for the owner
        ownerPrivateKey = uint256(keccak256(abi.encodePacked("owner key")));
        ownerAddress = vm.addr(ownerPrivateKey);

        // Deploy the SimpleAccountFactory with the entry point
        factory = new SimpleAccountFactory(entryPoint);
    }

    function testValidateSignature() public {
        // Define a unique salt for each account
        uint256 salt = uint256(keccak256(abi.encodePacked("unique salt")));

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
}
