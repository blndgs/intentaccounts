// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title xCallDataLib
 * @dev Library for handling cross-chain UserOperations in ERC-4337 compatible wallets with packed callData
 */
library XChainLib {
    // Maximum allowed callData length for a UserOperation (14KB)
    uint256 internal constant MAX_COMBINED_CALLDATA_LENGTH = 40960; // MAX_CALLDATA_LENGTH * 4
    uint256 internal constant MAX_CALLDATA_LENGTH = 10240;
    uint256 internal constant MAX_CALLDATA_COUNT = 4;
    uint256 internal constant MAX_CHAIN_ID = 0xFFFF;

    // Custom errors
    error InvalidCallDataLength(uint256 length);
    error InvalidEncodedData();
    error InvalidNumberOfCallData(uint256 count);
    error ChainDataTooShort();
    error ZeroChainId();

    struct xCallData {
        uint16 chainId;
        bytes callData;
    }

    /**
     * @notice Efficiently detects if the calldata is for multi-chain operations.
     * Warning: it does not check if the calldata is a non-zero meaningful value.
     *
     * The function returns false if:
     * - The input data is invalid or cannot be parsed.
     * - Parsed chain id is 0.
     * - Any nested calldata length is 0.
     * - The number of operations is less than 2 or more than 4.
     * - The calldata length doesn't match the sum of all operation lengths.
     *
     * @param callData The calldata to check
     * @return bool True if the calldata appears to be for multi-chain operations, false otherwise
     */
    function isXChainCallData(bytes calldata callData) external pure returns (bool) {
        bool isValid;
        assembly {
            isValid := 1
            let length := callData.length
            // Check if calldata has at least 5 bytes (1 for numOps + 4 for first operation)
            if lt(length, 5) { isValid := 0 }
            if isValid {
                let numOps := byte(0, calldataload(callData.offset)) // Read number of operations
                if or(lt(numOps, 2), gt(numOps, 4)) { isValid := 0 } // Check numOps bounds (2 to 4)
                let currentPos := add(callData.offset, 1) // Start position after numOps byte
                let i := 0
                for {} and(lt(i, numOps), isValid) { i := add(i, 1) } {
                    if gt(add(currentPos, 4), add(callData.offset, length)) {
                        isValid := 0
                        break
                    }

                    // Read chainId (2 bytes)
                    let chainId := shr(240, calldataload(currentPos))
                    // chain id cannot be 0
                    if eq(chainId, 0) {
                        isValid := 0
                        break
                    }
                    // Read dataLength (2 bytes after chainId)
                    let dataLength := shr(240, calldataload(add(currentPos, 2)))

                    // Check if dataLength is 0 or if remaining calldata is not long enough for this operation
                    if or(
                        or(eq(dataLength, 0), gt(dataLength, MAX_CALLDATA_LENGTH)),
                        gt(add(currentPos, add(4, dataLength)), add(callData.offset, length))
                    ) {
                        isValid := 0
                        break
                    }

                    // Update position to the next operation
                    currentPos := add(currentPos, add(4, dataLength))
                }

                if isValid { isValid := eq(currentPos, add(callData.offset, length)) } // Ensure all calldata is processed
            }
        }
        return isValid;
    }

    /* Solidity version of the above assembly code
    function isXChainCallDataSol(bytes calldata callData) public pure returns (bool) {
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
     * by favoring up to 4 static checks instead of looping.
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
        if (numOps < 2 || numOps > 4) revert InvalidNumberOfCallData(numOps);

        uint256 offset = 1;
        uint16 chainId;

        // Check first chain
        (chainId, offset) = readChainId(encodedData, offset);
        if (chainId == 0) revert ZeroChainId();
        if (chainId == targetChainId) {
            return readCalldata(encodedData, offset);
        }
        offset = skipCalldata(encodedData, offset);

        // If only one operation, return empty
        if (numOps == 1) return new bytes(0);

        // Check second chain
        (chainId, offset) = readChainId(encodedData, offset);
        if (chainId == 0) revert ZeroChainId();
        if (chainId == targetChainId) {
            return readCalldata(encodedData, offset);
        }
        offset = skipCalldata(encodedData, offset);

        // If only two operations, return empty
        if (numOps == 2) return new bytes(0);

        // Check third chain
        (chainId, offset) = readChainId(encodedData, offset);
        if (chainId == 0) revert ZeroChainId();
        if (chainId == targetChainId) {
            return readCalldata(encodedData, offset);
        }
        offset = skipCalldata(encodedData, offset);

        // If only three operations, return empty
        if (numOps == 3) return new bytes(0);

        // Check fourth chain
        (chainId, offset) = readChainId(encodedData, offset);
        if (chainId == 0) revert ZeroChainId();
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
        if (calldataLength > MAX_CALLDATA_LENGTH) revert InvalidCallDataLength(calldataLength);
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
        if (calldataLength > MAX_CALLDATA_LENGTH) revert InvalidCallDataLength(calldataLength);
        return offset + 2 + calldataLength;
    }

    /**
     * Provides the cross-chain chain_id for a multichain userOp if the calldata provides the 
     * cross-chain calldata for a multichain userOp by concatenating chain IDs from the encoded 
     * cross-chain call data into the lower 64-bits of the returned uint256 value. 
     * @dev This function extracts and combines chain IDs from the encoded data structure,
     *      preserving their original order. The concatIds is a packed uint64 where:
     *      - The most significant 16 bits contain the first operation's chain ID.
     *      - Each subsequent 16-bit segment contains the next operation's chain ID.
     *      - Minimum chains are 2 (least significant 32-bits) and maximum are 4.
     *      - Up to 4 chain IDs can be packed, utilizing at most 64 bits.
     *
     * For example, given chain IDs [0x0001, 0x0005, 0x0064, 0x03E8], the output would be:
     * 0x0001000500640388
     * Which breaks down as:
     * - 0x0001 (Most significant 16 bits, representing chain ID 1)
     * - 0x0005 (Next 16 bits, representing chain ID 5)
     * - 0x0064 (Next 16 bits, representing chain ID 100)
     * - 0x03E8 (Least significant 16 bits, representing chain ID 1000)
     *
     * Visualized in 16-bit segments: 0x0001 | 0x0005 | 0x0064 | 0x03E8
     *
     * The function returns targetChainId if:
     * - The input data is invalid or cannot be parsed.
     * - the targetChainId is 0 or exceeds MAX_CHAIN_ID.
     * - Any parsed chain id is 0.
     * - None of the parsed chain IDs match the targetChainId.
     * - The input is a conventional single userOp non-prefixed calldata.
     * - The number of operations is less than 2 or more than 4.
     *
     * @param encodedData The encoded cross-chain call data containing chain IDs and their associated call data.
     * @param targetChainId The default chain ID to return in case of invalid input or no matching chain ID.
     * @return concatIds A uint256 value with concatenated chain IDs, ordered from most to least significant bits,
     *                   or targetChainId if conditions are not met.
     */
    function getXChainIdsSol(bytes calldata encodedData, uint256 targetChainId)
        external
        pure
        returns (uint256 concatIds)
    {
        if (targetChainId == 0 || targetChainId > MAX_CHAIN_ID) return targetChainId; // Invalid target chain ID

        if (encodedData.length < 5 || encodedData.length > MAX_COMBINED_CALLDATA_LENGTH) return targetChainId;

        uint8 numOps = uint8(encodedData[0]);
        if (numOps < 2 || numOps > 4) return targetChainId; // Invalid number of operations

        uint256 offset = 1;
        bool matchFound = false;

        for (uint8 i = 0; i < numOps; i++) {
            if (offset + 4 > encodedData.length) return targetChainId; // Not enough data for this operation

            uint16 chainId = uint16(bytes2(encodedData[offset:offset + 2]));
            if (chainId == 0) return targetChainId; // Invalid chain ID

            // Check if the parsed chainId matches targetChainId
            if (chainId == targetChainId) {
                matchFound = true;
            }

            concatIds = (concatIds << 16) | chainId;

            uint16 calldataLength = uint16(bytes2(encodedData[offset + 2:offset + 4]));
            if (calldataLength > MAX_CALLDATA_LENGTH) return targetChainId;

            offset += 4 + calldataLength;

            if (offset > encodedData.length) return targetChainId; // Calldata length exceeds available data
        }

        if (offset != encodedData.length) return targetChainId; // Extra data at the end

        // If no match was found, return targetChainId
        return matchFound ? concatIds : targetChainId;
    }

    /**
     * Yul version: provides the cross-chain chain_id for a multichain userOp if the calldata 
     * provides the cross-chain calldata for a multichain userOp by concatenating chain IDs 
     * from the encoded cross-chain call data into the lower 64-bits of the returned uint256 
     * value. 
     * @dev This function extracts and combines chain IDs from the encoded data structure,
     *      preserving their original order. The concatIds is a packed uint256 where:
     *      - The most significant 16 bits contain the first operation's chain ID.
     *      - Minimum chains are 2 (least significant 32-bits) and maximum are 4.
     *      - Up to 4 chain IDs can be packed, utilizing at most 64 bits.
     *
     * For example, given chain IDs [0x0001, 0x0005, 0x0064, 0x03E8], the output would be:
     * 0x0001000500640388
     * Which breaks down as:
     * - 0x0001 (Most significant 16 bits, representing chain ID 1)
     * - 0x0005 (Next 16 bits, representing chain ID 5)
     * - 0x0064 (Next 16 bits, representing chain ID 100)
     * - 0x03E8 (Least significant 16 bits of the used bits, representing chain ID 1000)
     *
     * Visualized in 16-bit segments: 0x0001 | 0x0005 | 0x0064 | 0x03E8
     *
     * The function returns targetChainId if:
     * - Any parsed chain id is 0.
     * - the targetChainId is 0 or exceeds MAX_CHAIN_ID.
     * - The input data is invalid or cannot be parsed.
     * - None of the parsed chain IDs match the targetChainId.
     * - The input is a conventional single userOp non-prefixed calldata.
     * - The number of operations is less than 2 or more than 4.
     *
     * @param encodedData The encoded cross-chain call data containing chain IDs and their associated call data.
     * @param targetChainId The current block chain ID. This returns in case of invalid input or no matching chain ID.
     * @return concatIds A uint256 value with concatenated chain IDs, ordered from most to least significant bits,
     *                   or targetChainId if conditions are not met.
     */
    function getXChainIds(bytes calldata encodedData, uint256 targetChainId)
        public
        pure
        returns (uint256 concatIds)
    {
        assembly {
            if or(iszero(targetChainId), gt(targetChainId, MAX_CHAIN_ID)) {
                // currently only 16-bit chain IDs are supported
                mstore(0, targetChainId) // redundant for 0 value? better safe than sorry
                return(0, 32)
            }

            if gt(encodedData.length, MAX_COMBINED_CALLDATA_LENGTH) {
                mstore(0, targetChainId)
                return(0, 32)
            }

            // Initialize concatIds with targetChainId
            concatIds := targetChainId

            // Check if the input data is long enough to contain at least one operation
            if lt(calldatasize(), add(encodedData.offset, 5)) {
                // Return targetChainId if data is too short
                mstore(0, targetChainId)
                return(0, 32)
            }

            // Extract the number of operations from the first byte
            let numOps := shr(248, calldataload(encodedData.offset))

            // Check if the number of operations is valid (between 2 and 4)
            if or(lt(numOps, 2), gt(numOps, 4)) {
                // Return targetChainId if number of operations is invalid
                mstore(0, targetChainId)
                return(0, 32)
            }

            // Calculate the start and end offsets of the encoded data
            let offset := add(encodedData.offset, 1)
            let endOffset := add(encodedData.offset, encodedData.length)

            // Reset concatIds to 0 before concatenation
            concatIds := 0

            // Flag to check if any parsed chainId matches targetChainId
            let matchFound := 0

            for { let i := 0 } lt(i, numOps) { i := add(i, 1) } {
                // Check if there's enough data for the current operation
                if gt(add(offset, 4), endOffset) {
                    // Return targetChainId if data is insufficient
                    mstore(0, targetChainId)
                    return(0, 32)
                }

                // Extract the chain ID (2 bytes)
                let chainId := and(shr(240, calldataload(offset)), 0xFFFF)
                // zero chainid is invalid
                if eq(chainId, 0) {
                    mstore(0, targetChainId)
                    return(0, 32)
                }

                // Check if the parsed chainId matches targetChainId
                if eq(chainId, targetChainId) { matchFound := 1 }

                concatIds := or(shl(16, concatIds), chainId)

                // Extract the calldata length (next 2 bytes after the chain ID)
                let calldataLength := and(shr(240, calldataload(add(offset, 2))), 0xFFFF)
                if gt(calldataLength, MAX_CALLDATA_LENGTH) {
                    mstore(0, targetChainId)
                    return(0, 32)
                }

                // Move the offset to the next operation
                offset := add(offset, add(calldataLength, 4))

                // Check if we've exceeded the available data
                if gt(offset, endOffset) {
                    // Return targetChainId if we've exceeded available data
                    mstore(0, targetChainId)
                    return(0, 32)
                }
            }

            // Check if we've consumed exactly all the input data
            if iszero(eq(offset, endOffset)) {
                // Return targetChainId if there's extra data
                mstore(0, targetChainId)
                return(0, 32)
            }

            // concatenation was successful
            // Check if any chainId matched targetChainId
            switch matchFound
            case 0 {
                // unathorized chain, return targetChainId
                mstore(0, targetChainId)
            }
            default {
                // If a match was found, return the concatenated chain IDs
                mstore(0, concatIds)
            }
            return(0, 32)
        }
    }
}
