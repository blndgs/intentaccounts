// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title xCallDataLib
 * @dev Library for handling cross-chain UserOperations in ERC-4337 compatible wallets with packed callData
 */
library XChainLib {
    // Maximum allowed callData length for a UserOperation (14KB)
    uint256 internal constant MAX_COMBINED_CALLDATA_LENGTH = 14336; // MAX_CALLDATA_LENGTH * 2
    uint256 internal constant MAX_CALLDATA_LENGTH = 7168;
    uint256 internal constant MAX_CALLDATA_COUNT = 4;

    // Custom errors
    error CombinedCallDataTooLong(uint256 length);
    error InvalidCallDataLength(uint256 length);
    error CallDataTooLong(uint256 length);
    error InvalidEncodedData();
    error InvalidNumberOfCallData(uint256 count);
    error ChainDataTooShort();

    struct xCallData {
        uint16 chainId;
        bytes callData;
    }

    /**
     * @notice Efficiently detects if the calldata is for multi-chain operations
     * @param callData The calldata to check
     * @return bool True if the calldata appears to be for multi-chain operations, false otherwise
     */
    function isXChainCallData(bytes calldata callData) public pure returns (bool) {
        bool isValid;
        assembly {
            isValid := 1
            let length := callData.length
            if lt(length, 5) { isValid := 0 } // Check if length is less than 5
            if isValid {
                let numOps := byte(0, calldataload(callData.offset)) // Read number of operations
                if or(eq(numOps, 0), gt(numOps, 4)) { isValid := 0 } // Check numOps bounds
                let currentPos := add(callData.offset, 1) // Start position after numOps byte
                let i := 0
                for {} and(lt(i, numOps), isValid) { i := add(i, 1) } {
                    if gt(add(currentPos, 4), add(callData.offset, length)) {
                        isValid := 0
                        break
                    }
                    
                    // Read chainId (2 bytes)
                    let chainId := shr(240, calldataload(currentPos))
                    // Read dataLength (2 bytes after chainId)
                    let dataLength := shr(240, calldataload(add(currentPos, 2)))
    
                    // Check for valid chainId and dataLength
                    if or(eq(chainId, 0), or(eq(dataLength, 0), gt(add(currentPos, add(4, dataLength)), add(callData.offset, length)))) {
                        isValid := 0
                        break
                    }
    
                    // Update position to the next operation
                    currentPos := add(currentPos, add(4, dataLength))
                }
    
                if isValid {
                    isValid := eq(currentPos, add(callData.offset, length)) // Ensure all calldata is processed
                }
            }
        }
        return isValid;
    }

    /* Solidity version of the above assembly code
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
    */
    
    /**
     * @notice Efficiently finds and returns the calldata for a specific chain ID (up to 4 chains)
     * @dev Encoding structure:
     * +-------------------+-------------------+-------------------+
     * |    Number of Ops  |       UserOp 1    |      UserOp 2     |
     * |      (1 byte)     |                   |                   |
     * +-------------------+-------------------+-------------------+
     * |        0x02       |     Chain 1 Data  |    Chain 2 Data   |
     * +-------------------+-------------------+-------------------+
     *                     |                   |
     *                     v                   v
     *             +---------------+   +---------------+
     *             | Chain ID (2B) |   | Chain ID (2B) |
     *             +---------------+   +---------------+
     *             | Length  (2B)  |   | Length  (2B)  |
     *             +---------------+   +---------------+
     *             | Calldata      |   | Calldata      |
     *             | (Variable)    |   | (Variable)    |
     *             +---------------+   +---------------+
     * @param encodedData The encoded multi-chain UserOp data
     * @param targetChainId The chain ID to find the calldata for (range: 1 to 65535)
     * @return calldataContent The calldata for the specified chain ID, or an empty bytes array if not found
     */
    function extractXChainCallData(bytes calldata encodedData, uint16 targetChainId)
        external
        pure
        returns (bytes memory)
    {
        if (encodedData.length < 1) revert InvalidEncodedData();

        uint8 numOps = uint8(encodedData[0]);
        if (numOps == 0 || numOps > 4) revert InvalidNumberOfCallData(numOps);

        uint256 offset = 1;
        uint16 chainId;

        // Check first chain
        (chainId, offset) = readChainId(encodedData, offset);
        if (chainId == targetChainId) {
            return readCalldata(encodedData, offset);
        }
        offset = skipCalldata(encodedData, offset);

        // If only one operation, return empty
        if (numOps == 1) return new bytes(0);

        // Check second chain
        (chainId, offset) = readChainId(encodedData, offset);
        if (chainId == targetChainId) {
            return readCalldata(encodedData, offset);
        }
        offset = skipCalldata(encodedData, offset);

        // If only two operations, return empty
        if (numOps == 2) return new bytes(0);

        // Check third chain
        (chainId, offset) = readChainId(encodedData, offset);
        if (chainId == targetChainId) {
            return readCalldata(encodedData, offset);
        }
        offset = skipCalldata(encodedData, offset);

        // If only three operations, return empty
        if (numOps == 3) return new bytes(0);

        // Check fourth chain
        (chainId, offset) = readChainId(encodedData, offset);
        if (chainId == targetChainId) {
            return readCalldata(encodedData, offset);
        }

        // If not found, return empty
        return new bytes(0);
    }

    /**
     * @notice Helper function to read chain ID from encoded data
     * @param encodedData The encoded multi-chain UserOp data
     * @param offset The current offset in the encoded data
     * @return chainId The chain ID (range: 1 to 65535)
     * @return newOffset The new offset after reading the chain ID
     */
    function readChainId(bytes calldata encodedData, uint256 offset)
        private
        pure
        returns (uint16 chainId, uint256 newOffset)
    {
        if (encodedData.length < offset + 2) revert ChainDataTooShort();
        chainId = uint16(bytes2(encodedData[offset:offset + 2]));
        newOffset = offset + 2;
    }

    /**
     * @notice Helper function to read calldata from encoded data
     * @param encodedData The encoded multi-chain UserOp data
     * @param offset The current offset in the encoded data
     * @return calldataContent The calldata
     */
    function readCalldata(bytes calldata encodedData, uint256 offset) private pure returns (bytes memory) {
        if (encodedData.length < offset + 2) revert ChainDataTooShort();
        uint16 calldataLength = uint16(bytes2(encodedData[offset:offset + 2]));
        offset += 2;
        if (encodedData.length < offset + calldataLength) {
            revert ChainDataTooShort();
        }
        return encodedData[offset:offset + calldataLength];
    }

    /**
     * @notice Helper function to skip calldata in encoded data
     * @param encodedData The encoded multi-chain UserOp data
     * @param offset The current offset in the encoded data
     * @return newOffset The new offset after skipping the calldata
     */
    function skipCalldata(bytes calldata encodedData, uint256 offset) private pure returns (uint256) {
        if (encodedData.length < offset + 2) revert ChainDataTooShort();
        uint16 calldataLength = uint16(bytes2(encodedData[offset:offset + 2]));
        return offset + 2 + calldataLength;
    }
}
