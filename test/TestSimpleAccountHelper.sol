// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import "../src/IntentUserOperation.sol";
import "./TestBytesHelper.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IntentSimpleAccountFactory} from "../src/IntentSimpleAccountFactory.sol";
import "../src/IntentSimpleAccount.sol";
import "forge-std/Test.sol";

library TestSimpleAccountHelper {
    using ECDSA for bytes32;

    uint256 private constant SIGNATURE_LENGTH = 65;
    uint256 private constant OPTYPE_LENGTH = 2;

    // Custom errors
    error EndLessThanStart();
    error EndOutOfBounds(uint256 dataLength, uint256 end);
    error StartOutOfBounds(uint256 dataLength, uint256 start);

    /**
     * @notice Generates the initCode for creating a new account using a wallet factory
     * @dev This function is used to create the initCode field in a UserOperation for account creation
     * @param factory The address of the wallet factory contract
     * @param owner The address that will own the new account
     * @param salt A unique value to ensure different wallet addresses for the same owner
     * @return bytes The initCode to be used in a UserOperation
     *
     * @custom:example
     * Input:
     *   factory: 0x1234567890123456789012345678901234567890
     *   owner: 0xaabbccddeeaabbccddeeaabbccddeeaabbccddee
     *   salt: 0x0000000000000000000000000000000000000000000000000000000000000001
     *
     * Output:
     *   0x1234567890123456789012345678901234567890
     *   5fbfb9cf
     *   000000000000000000000000aabbccddeeaabbccddeeaabbccddeeaabbccddee
     *   0000000000000000000000000000000000000000000000000000000000000001
     *
     * Explanation:
     * - First 20 bytes: Factory address
     * - Next 4 bytes: Function selector for 'createAccount(address,uint256)'
     * - Next 32 bytes: Owner address (padded)
     * - Last 32 bytes: Salt value
     */
    function getInitCode(IntentSimpleAccountFactory factory, address owner, uint256 salt)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(address(factory), abi.encodeWithSelector(factory.createAccount.selector, owner, salt));
    }

    /**
     * @notice Creates cross-chain call data according to the linked hash specification
     * @param callData The call data for the operation
     * @param otherChainHash The hash of the UserOperation on the other chain
     * @return bytes The encoded cross-chain call data
     */
    function createCrossChainCallData(bytes memory callData, bytes32 otherChainHash)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint16(0xFFFF), // opType marker
            uint16(callData.length),
            callData,
            otherChainHash
        );
    }

    /**
     * @notice Creates a cross-chain UserOperation for testing
     * @param sender The address of the account initiating the operation
     * @param nonce The nonce of the account
     * @param callData The call data for the operation
     * @param callGasLimit The gas limit for the call
     * @param verificationGasLimit The gas limit for verification
     * @param preVerificationGas The gas cost before verification
     * @param maxFeePerGas The max fee per gas
     * @param maxPriorityFeePerGas The max priority fee per gas
     * @param otherChainHash The hash of the UserOperation on the other chain
     * @return UserOperation The generated cross-chain UserOperation
     */
    function createCrossChainUserOp(
        address sender,
        uint256 nonce,
        bytes memory callData,
        uint256 callGasLimit,
        uint256 verificationGasLimit,
        uint256 preVerificationGas,
        uint256 maxFeePerGas,
        uint256 maxPriorityFeePerGas,
        bytes32 otherChainHash
    ) internal pure returns (UserOperation memory) {
        bytes memory crossChainCallData = createCrossChainCallData(callData, otherChainHash);

        return UserOperation({
            sender: sender,
            nonce: nonce,
            initCode: "",
            callData: crossChainCallData,
            callGasLimit: callGasLimit,
            verificationGasLimit: verificationGasLimit,
            preVerificationGas: preVerificationGas,
            maxFeePerGas: maxFeePerGas,
            maxPriorityFeePerGas: maxPriorityFeePerGas,
            paymasterAndData: "",
            signature: ""
        });
    }

    /**
     * @notice Creates a conventional UserOperation for testing
     * @param sender The address of the account initiating the operation
     * @param nonce The nonce of the account
     * @param callData The call data for the operation
     * @param callGasLimit The gas limit for the call
     * @param verificationGasLimit The gas limit for verification
     * @param preVerificationGas The gas cost before verification
     * @param maxFeePerGas The max fee per gas
     * @param maxPriorityFeePerGas The max priority fee per gas
     * @return UserOperation The generated conventional UserOperation
     */
    function createConventionalUserOp(
        address sender,
        uint256 nonce,
        bytes memory callData,
        uint256 callGasLimit,
        uint256 verificationGasLimit,
        uint256 preVerificationGas,
        uint256 maxFeePerGas,
        uint256 maxPriorityFeePerGas
    ) internal pure returns (UserOperation memory) {
        return UserOperation({
            sender: sender,
            nonce: nonce,
            initCode: "",
            callData: callData,
            callGasLimit: callGasLimit,
            verificationGasLimit: verificationGasLimit,
            preVerificationGas: preVerificationGas,
            maxFeePerGas: maxFeePerGas,
            maxPriorityFeePerGas: maxPriorityFeePerGas,
            paymasterAndData: "",
            signature: ""
        });
    }

    function printUserOperation(UserOperation memory userOp) internal pure {
        console2.log("UserOperation:");
        console2.log("  Sender:", userOp.sender);
        console2.log("  Nonce:", userOp.nonce);
        console2.log("  InitCode length:", userOp.initCode.length);
        console2.log("  CallData length:", userOp.callData.length);
        console2.log("  CallGasLimit:", userOp.callGasLimit);
        console2.log("  VerificationGasLimit:", userOp.verificationGasLimit);
        console2.log("  PreVerificationGas:", userOp.preVerificationGas);
        console2.log("  MaxFeePerGas:", userOp.maxFeePerGas);
        console2.log("  MaxPriorityFeePerGas:", userOp.maxPriorityFeePerGas);
        console2.log("  PaymasterAndData length:", userOp.paymasterAndData.length);
        console2.log("  Signature length:", userOp.signature.length);

        // Print hexadecimal representation of initCode, callData, paymasterAndData, and signature
        console2.log("  InitCode (hex):");
        console2.logBytes(userOp.initCode);
        console2.log("  CallData (hex):");
        console2.logBytes(userOp.callData);
        console2.log("  PaymasterAndData (hex):");
        console2.logBytes(userOp.paymasterAndData);
        console2.log("  Signature (hex):");
        console2.logBytes(userOp.signature);
    }
}
