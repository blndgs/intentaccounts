// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import "../src/IntentUserOperation.sol";
import "./TestBytesHelper.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IntentSimpleAccountFactory} from "../src/IntentSimpleAccountFactory.sol";
import "../src/xchainlib.sol";
import "forge-std/Test.sol";
import "forge-std/Vm.sol";

library TestSimpleAccountHelper {
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 private constant SIGNATURE_LENGTH = 65;

    // Custom errors
    error EndLessThanStart();
    error EndOutOfBounds(uint256 dataLength, uint256 end);
    error StartOutOfBounds(uint256 dataLength, uint256 start);
    

    using XChainUserOpLib for UserOperation;

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

    function encodeXChainCallData(bytes memory sourceCallData, bytes memory destCallData) internal pure returns (bytes memory) {
        if (sourceCallData.length > XChainUserOpLib.MAX_CALLDATA_LENGTH) {
            revert XChainUserOpLib.SourceCallDataTooLong(sourceCallData.length);
        }
        if (destCallData.length > XChainUserOpLib.MAX_CALLDATA_LENGTH) {
            revert XChainUserOpLib.DestinationCallDataTooLong(destCallData.length);
        }
        if (sourceCallData.length + destCallData.length + 2 > XChainUserOpLib.MAX_COMBINED_CALLDATA_LENGTH) {
            revert XChainUserOpLib.CombinedCallDataTooLong(sourceCallData.length + destCallData.length + 2);
        }

        return abi.encodePacked(uint16(sourceCallData.length), sourceCallData, destCallData);
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
    
    /**
     * @dev Slices a bytes array to return a portion specified by the start and end indices.
     * @param data The bytes array to be sliced.
     * @param start The index in the bytes array where the slice begins.
     * @param end The index in the bytes array where the slice ends (exclusive).
     * @return result The sliced portion of the bytes array.
     * Note: The function reverts if the start index is not less than the end index,
     *       if start or end is out of the bounds of the data array.
     */
    function _slice(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory result) {
        if (end <= start) revert EndLessThanStart();
        if (end > data.length) revert EndOutOfBounds(data.length, end);
        if (start >= data.length) revert StartOutOfBounds(data.length, start);

        assembly {
            // Allocate memory for the result
            result := mload(0x40)
            mstore(result, sub(end, start)) // Set the length of the result
            let resultPtr := add(result, 0x20)

            // Copy the data from the start to the end
            for { let i := start } lt(i, end) { i := add(i, 0x20) } {
                let dataPtr := add(add(data, 0x20), i)
                mstore(add(resultPtr, sub(i, start)), mload(dataPtr))
            }

            // Update the free memory pointer
            mstore(0x40, add(resultPtr, sub(end, start)))
        }
    }
}
