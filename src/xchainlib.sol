// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import "forge-std/Test.sol";

/**
 * @title XChainLib
 * @dev Library for handling cross-chain UserOperations in ERC-4337 compatible wallets with packed callData
 */
library XChainLib {
    uint256 internal constant CALLDATA_LENGTH_SIZE = 2;
    uint256 internal constant HASH_LENGTH = 32;
    uint256 internal constant OPTYPE_LENGTH = 2;
    uint16 internal constant XC_MARKER = 0xFFFF;
    uint256 internal constant PLACEHOLDER_LENGTH = 2;
    uint256 internal constant HASHLIST_LENGTH_SIZE = 1;
    uint256 internal constant MIN_OP_COUNT = 2;
    uint256 internal constant MAX_OP_COUNT = 3;

    enum OpType {
        Conventional,
        CrossChain
    }

    // Custom errors
    error InvalidCallDataLength(uint256 length);

    /// Struct to hold parsed data from extraData
    struct xCallData {
        OpType opType;
        bytes32 callDataHash;
        bytes32[MAX_OP_COUNT] hashList;
        uint256 hashCount;
    }

    /**
     * @dev Identifies the OpType and extracts the callDataHash, hashList, and hashCount from the cross-chain call data.
     * @param extraData The cross-chain call data extracted from the signature.
     * @return xElems the xCallData struct containing the parsed data: opType, callDataHash, hashList, hashCount.
     */
    function parseXElems(bytes calldata extraData) internal pure returns (xCallData memory xElems) {
        // Initialize with default values
        xElems.opType = XChainLib.OpType.Conventional;
        xElems.hashCount = 0;

        uint256 extraDataLength = extraData.length;

        if (extraDataLength >= OPTYPE_LENGTH + CALLDATA_LENGTH_SIZE + HASHLIST_LENGTH_SIZE + PLACEHOLDER_LENGTH) {
            uint256 offset = 0;

            // Read the marker (2 bytes)
            uint16 marker = (uint16(uint8(extraData[offset])) << 8) | uint16(uint8(extraData[offset + 1]));
            offset += OPTYPE_LENGTH;

            if (marker == XC_MARKER) {
                // Set opType to CrossChain
                xElems.opType = XChainLib.OpType.CrossChain;

                // Read callDataLength (2 bytes)
                uint16 callDataLength = (uint16(uint8(extraData[offset])) << 8) | uint16(uint8(extraData[offset + 1]));
                offset += CALLDATA_LENGTH_SIZE;

                if (extraDataLength >= offset + callDataLength + HASHLIST_LENGTH_SIZE + PLACEHOLDER_LENGTH) {
                    // Extract callDataHash
                    xElems.callDataHash = keccak256(extraData[offset:offset + callDataLength]);
                    offset += callDataLength;

                    // Read hashListLength
                    uint8 hashListLength;
                    assembly {
                        // calldataload(add(extraData.offset, offset)) reads 32 bytes from calldata.
                        // shr(248, ...) shifts the loaded data right by 248 bits, moving the byte we want to the least significant position.
                        hashListLength := shr(248, calldataload(add(extraData.offset, offset)))
                    }
                    offset += HASHLIST_LENGTH_SIZE;

                    if (hashListLength >= MIN_OP_COUNT && hashListLength <= MAX_OP_COUNT) {
                        xElems.hashCount = hashListLength;

                        uint256 expectedLength = offset;

                        // Pre-calculate expected length based on entry sizes
                        for (uint256 i = 0; i < hashListLength; i++) {
                            uint256 entryOffset = expectedLength;

                            // Check if the next 2 bytes are the placeholder
                            uint16 possiblePlaceholder;
                            assembly {
                                possiblePlaceholder := shr(240, calldataload(add(extraData.offset, entryOffset)))
                            }

                            if (possiblePlaceholder == XC_MARKER) {
                                expectedLength += PLACEHOLDER_LENGTH;
                            } else {
                                expectedLength += HASH_LENGTH;
                            }
                        }

                        if (extraDataLength >= expectedLength) {
                            // Loop through hash list entries
                            for (uint256 i = 0; i < hashListLength; i++) {
                                uint256 entryOffset = offset;

                                // Check if the next 2 bytes are the placeholder
                                uint16 possiblePlaceholder;
                                assembly {
                                    possiblePlaceholder := shr(240, calldataload(add(extraData.offset, entryOffset)))
                                }

                                if (possiblePlaceholder == XC_MARKER) {
                                    // It's a placeholder
                                    xElems.hashList[i] = bytes32(uint256(XC_MARKER) << 240);
                                    offset += PLACEHOLDER_LENGTH;
                                } else {
                                    // It's a hash (32 bytes)
                                    bytes32 hashEntry;
                                    assembly {
                                        hashEntry := calldataload(add(extraData.offset, offset))
                                    }
                                    xElems.hashList[i] = hashEntry;
                                    offset += HASH_LENGTH;
                                }
                            }
                        } else {
                            // If not enough data for all hashes, set opType back to Conventional
                            xElems.opType = XChainLib.OpType.Conventional;
                        }
                    } else {
                        // If hashListLength is invalid, set opType back to Conventional
                        xElems.opType = XChainLib.OpType.Conventional;
                    }
                } else {
                    // If not enough data, set opType back to Conventional
                    xElems.opType = XChainLib.OpType.Conventional;
                }
            }
        }

        // Do NOT set callDataHash for conventional operations here
    }

    /// Computes the final hash for cross-chain operations
    /// @param initialOpHash The initial operation hash
    /// @param hashList Array of hashes including the placeholder
    /// @param hashCount Number of valid hashes in the hashList
    /// @return The computed cross-chain hash
    function computeCrossChainHash(bytes32 initialOpHash, bytes32[MAX_OP_COUNT] memory hashList, uint256 hashCount)
        internal
        pure
        returns (bytes32)
    {
        bool placeholderReplaced = false;
        for (uint256 i = 0; i < hashCount; i++) {
            if (hashList[i] == bytes32(uint256(XC_MARKER) << 240)) {
                hashList[i] = initialOpHash;
                placeholderReplaced = true;
                break;
            }
        }

        // If placeholder wasn't found, return the initial hash
        if (!placeholderReplaced) {
            return initialOpHash;
        }

        // Compute combined hash based on hashCount
        if (hashCount == MIN_OP_COUNT) {
            return keccak256(abi.encodePacked(hashList[0], hashList[1]));
        } else if (hashCount == MAX_OP_COUNT) {
            return keccak256(abi.encodePacked(hashList[0], hashList[1], hashList[2]));
        } else {
            // For hashCount == 1, use the single hash
            return keccak256(abi.encodePacked(hashList[0]));
        }
    }
}
