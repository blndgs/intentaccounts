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
            uint16(intent.length), // callDataLength (2 bytes)
            intent, // callData
            uint8(hashList.length) // hashListLength (1 byte)
        );

        for (uint256 i = 0; i < hashList.length; i++) {
            result = abi.encodePacked(result, hashList[i]);
        }

        return result;
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
     * @param hashListEntries The array of hash list entries (including the placeholder)
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
        bytes[] memory hashListEntries
    ) internal pure returns (UserOperation memory) {
        bytes memory crossChainCallData = createCrossChainCallData(callData, hashListEntries);

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

    function parseXElems(bytes calldata extraData) internal pure returns (XChainLib.xCallData memory xElems) {
        console2.log("parseXElems, extraData length:", extraData.length);
        console2.log("parseXElems, initial opType:", uint256(xElems.opType));
        console2.log("parseXElems, initial hashCount:", xElems.hashCount);

        // Initialize with default values
        xElems.opType = XChainLib.OpType.Conventional;
        xElems.hashCount = 0;

        uint256 extraDataLength = extraData.length;

        if (
            extraDataLength
                >= XChainLib.OPTYPE_LENGTH + XChainLib.CALLDATA_LENGTH_SIZE + XChainLib.HASHLIST_LENGTH_SIZE
                    + XChainLib.PLACEHOLDER_LENGTH
        ) {
            uint256 offset = 0;

            // Read the marker (2 bytes)
            uint16 marker = (uint16(uint8(extraData[offset])) << 8) | uint16(uint8(extraData[offset + 1]));
            offset += XChainLib.OPTYPE_LENGTH;

            if (marker == XChainLib.XC_MARKER) {
                // Set opType to CrossChain
                xElems.opType = XChainLib.OpType.CrossChain;
                console2.log("parseXElems, opType set to CrossChain");

                // Read callDataLength (2 bytes)
                uint16 callDataLength = (uint16(uint8(extraData[offset])) << 8) | uint16(uint8(extraData[offset + 1]));
                console2.log("parseXElems, callDataLength:", callDataLength);
                offset += XChainLib.CALLDATA_LENGTH_SIZE;

                if (
                    extraDataLength
                        >= offset + callDataLength + XChainLib.HASHLIST_LENGTH_SIZE + XChainLib.PLACEHOLDER_LENGTH
                ) {
                    // Extract callDataHash
                    xElems.callDataHash = keccak256(extraData[offset:offset + callDataLength]);
                    console2.log("parseXElems, callDataHash:");
                    console2.logBytes32(xElems.callDataHash);
                    offset += callDataLength;

                    // Read hashListLength
                    uint8 hashListLength = uint8(extraData[offset]);
                    console2.log("parseXElems, hashListLength:", hashListLength);
                    offset += XChainLib.HASHLIST_LENGTH_SIZE;

                    if (hashListLength >= XChainLib.MIN_OP_COUNT && hashListLength <= XChainLib.MAX_OP_COUNT) {
                        xElems.hashCount = hashListLength;
                        console2.log("parseXElems, hashCount set to:", xElems.hashCount);

                        uint256 expectedLength = offset;

                        // Pre-calculate expected length based on entry sizes
                        for (uint256 i = 0; i < hashListLength; i++) {
                            uint256 entryOffset = expectedLength;

                            // Check if the next 2 bytes are the placeholder
                            uint16 possiblePlaceholder;
                            assembly {
                                possiblePlaceholder := shr(240, calldataload(add(extraData.offset, entryOffset)))
                            }
                            console2.log("parseXElems, possiblePlaceholder at index", i);
                            console2.log("parseXElems, possiblePlaceholder :", possiblePlaceholder);

                            if (possiblePlaceholder == XChainLib.XC_MARKER) {
                                console2.log("parseXElems, placeholder found at index", i);
                                expectedLength += XChainLib.PLACEHOLDER_LENGTH;
                            } else {
                                console2.log("parseXElems, hash found at index", i);
                                expectedLength += XChainLib.HASH_LENGTH;
                            }
                        }

                        console2.log("parseXElems, expectedLength:", expectedLength);
                        if (extraDataLength >= expectedLength) {
                            // Loop through hash list entries
                            for (uint256 i = 0; i < hashListLength; i++) {
                                uint256 entryOffset = offset;

                                // Check if the next 2 bytes are the placeholder
                                uint16 possiblePlaceholder;
                                assembly {
                                    possiblePlaceholder := shr(240, calldataload(add(extraData.offset, entryOffset)))
                                }
                                console2.log("parseXElems, possiblePlaceholder at index", i, ":", possiblePlaceholder);

                                if (possiblePlaceholder == XChainLib.XC_MARKER) {
                                    // It's a placeholder
                                    xElems.hashList[i] = bytes32(uint256(XChainLib.XC_MARKER) << 240);
                                    console2.log("parseXElems, placeholder stored in hashList[", i, "]");
                                    offset += XChainLib.PLACEHOLDER_LENGTH;
                                } else {
                                    // It's a hash (32 bytes)
                                    bytes32 hashEntry;
                                    assembly {
                                        hashEntry := calldataload(add(extraData.offset, offset))
                                    }
                                    xElems.hashList[i] = hashEntry;
                                    console2.log("parseXElems, hashList[", i, "]:");
                                    console2.logBytes32(xElems.hashList[i]);
                                    offset += XChainLib.HASH_LENGTH;
                                }
                            }
                        } else {
                            // If not enough data for all hashes, set opType back to Conventional
                            xElems.opType = XChainLib.OpType.Conventional;
                            console2.log("parseXElems, not enough data for all hashes, opType set to Conventional");
                        }
                    } else {
                        // If hashListLength is invalid, set opType back to Conventional
                        xElems.opType = XChainLib.OpType.Conventional;
                        console2.log("parseXElems, invalid hashListLength, opType set to Conventional");
                    }
                } else {
                    // If not enough data, set opType back to Conventional
                    xElems.opType = XChainLib.OpType.Conventional;
                    console2.log("parseXElems, not enough data, opType set to Conventional");
                }
            }
        }

        // Do NOT set callDataHash for conventional operations here
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
