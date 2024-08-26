// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./IntentUserOperation.sol";
import {console2} from "forge-std/console2.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";

/**
 * @title CrossChainUserOpLib
 * @dev Library for handling cross-chain UserOperations in ERC-4337 compatible wallets with packed calldata
 */
library XChainUserOpLib {
    // Maximum allowed calldata length for a UserOperation (14KB)
    uint256 internal constant MAX_COMBINED_CALLDATA_LENGTH = 14438; // 2 bytes (length) + 14436 bytes for 2x userOp callData
    uint256 internal constant MAX_CALLDATA_LENGTH = 7168;

    enum ChainState {
        SAME_CHAIN,
        SOURCE_CHAIN,
        DESTINATION_CHAIN
    }

    // Custom errors
    error CombinedCallDataTooLong(uint256 length);
    error InvalidCallDataLength(uint256 length);
    error SourceCallDataTooLong(uint256 length);
    error DestinationCallDataTooLong(uint256 length);
    error EmptySourceCallData();
    error EmptyDestinationCallData();

    /**
     * @dev Checks if a UserOperation's callData belongs to a cross-chain operation
     * @param callData The UserOperation callData to check
     * @return bool True if it's a cross-chain operation, false otherwise
     */
    function isXChainCallData(bytes calldata callData) internal pure returns (bool) {
        uint256 combinedLength = callData.length;
        if (combinedLength <= 2 || combinedLength > MAX_COMBINED_CALLDATA_LENGTH) return false;
        uint16 sourceLength = uint16(bytes2(callData[:2]));
        return sourceLength <= MAX_CALLDATA_LENGTH && combinedLength - 2 <= MAX_COMBINED_CALLDATA_LENGTH;
    }

    /**
     * @dev Extracts the relevant calldata based on the chain state
                let currentPos := add(callData.offset, 1) // Start position after numOps byte
     * @param callData The combined calldata
     * @return bytes The extracted calldata relevant to the current chain state
     * @notice When ChainState is SOURCE_CHAIN, the destination calldata can be empty or not set
     * @notice When ChainState is DESTINATION_CHAIN, the source calldata can be empty (represented by a sourceCallDataLength of 0)
     */
    function extractXChainCallData(ChainState state, bytes calldata callData) internal pure returns (bytes memory) {
        uint256 combinedLength = callData.length;
        if (combinedLength > MAX_COMBINED_CALLDATA_LENGTH) {
            revert CombinedCallDataTooLong(combinedLength);
        }

        if (state == ChainState.SAME_CHAIN) {
            return callData;
        }

        if (combinedLength < 2) {
            revert InvalidCallDataLength(combinedLength);
        }

        uint16 sourceCallDataLength = uint16(bytes2(callData[:2]));
        if (sourceCallDataLength > MAX_CALLDATA_LENGTH) {
            revert SourceCallDataTooLong(sourceCallDataLength);
        }
        if (combinedLength - 2 > MAX_CALLDATA_LENGTH * 2) {
            revert DestinationCallDataTooLong(combinedLength - 2 - sourceCallDataLength);
        }

        if (state == ChainState.SOURCE_CHAIN) {
            if (sourceCallDataLength == 0) {
                revert EmptySourceCallData();
    function isXChainCallData2(bytes calldata callData) public pure returns (bool) {
        if (callData.length < 5) {
            return false;
        }

        uint8 numOps = uint8(callData[0]);
        if (numOps == 0 || numOps > MAX_CALLDATA_COUNT) {
            return false;
        }

        uint256 currentPos = 1;
        for (uint8 i = 0; i < numOps; i++) {
            if (currentPos + 4 > callData.length) {
                return false;
            }

            uint16 chainId = uint16(bytes2(callData[currentPos:currentPos + 2]));
            if (chainId == 0) {
                return false;
            }

            uint16 dataLength = uint16(bytes2(callData[currentPos + 2:currentPos + 4]));
            if (dataLength == 0 || currentPos + 4 + dataLength > callData.length) {
                return false;
            }

            currentPos += 4 + dataLength;
        }

        return currentPos == callData.length;
    }
    }
}
