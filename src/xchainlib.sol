// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

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

    /// Struct to hold parsed data from xData
    struct xCallData {
        OpType opType;
        bytes32 callDataHash;
        bytes32[MAX_OP_COUNT] hashList;
        uint256 hashCount;
    }

    /**
     * @dev Parses cross-chain call data (xdata) to extract operation type, callDataHash, hashList, and hashCount.
     * This function uses inline assembly for gas optimization.
     *
     * @param xData The cross-chain call data extracted from the signature.
     * @return xElems The xCallData struct containing the parsed data: opType, callDataHash, hashList, hashCount.
     *
     * The structure of xdata is as follows:
     * - Marker (2 bytes): XC_MARKER
     * - callDataLength (2 bytes): length of callData
     * - callData (callDataLength bytes): Intent JSON
     * - hashListLength (1 byte): number of hashes in hashList
     * - hashList: list of hashes or placeholders (variable length)
     *
     * This function checks for the marker to determine if the operation is cross-chain.
     * It then reads the callDataLength and extracts the callDataHash.
     * It reads the hashListLength and parses the hashList entries, which can be either a placeholder (2 bytes) or a hash (32 bytes).
     */
    function parseXElems(bytes calldata xData) internal pure returns (xCallData memory xElems) {
        uint256 xDataLength = xData.length;
        if (xDataLength >= OPTYPE_LENGTH + CALLDATA_LENGTH_SIZE + HASHLIST_LENGTH_SIZE + PLACEHOLDER_LENGTH) {
            uint16 marker;
            assembly {
                // Read the x-chain marker (2 bytes)
                marker := shr(240, calldataload(xData.offset))
            }

            if (marker == XC_MARKER) {
                xElems.opType = XChainLib.OpType.CrossChain;

                uint256 offset = OPTYPE_LENGTH + CALLDATA_LENGTH_SIZE;

                uint16 callDataLength;
                assembly {
                    // Read callDataLength (2 bytes)
                    callDataLength := shr(240, calldataload(add(xData.offset, OPTYPE_LENGTH)))
                }

                if (xDataLength >= offset + callDataLength + HASHLIST_LENGTH_SIZE + PLACEHOLDER_LENGTH) {
                    // Extract callDataHash
                    xElems.callDataHash = keccak256(xData[offset:offset + callDataLength]);
                    offset += callDataLength;

                    // Read hashListLength
                    uint8 hashListLength;
                    assembly {
                        // calldataload(add(xData.offset, offset)) reads 32 bytes from calldata.
                        // shr(248, ...) shifts the loaded data right by 248 bits, moving the byte we want to the least significant position.
                        hashListLength := shr(248, calldataload(add(xData.offset, offset)))
                    }
                    offset += HASHLIST_LENGTH_SIZE;

                    if (hashListLength >= MIN_OP_COUNT && hashListLength <= MAX_OP_COUNT) {
                        xElems.hashCount = hashListLength;

                        uint256 i;
                        bool parsingFailed = false;

                        for (i = 0; i < hashListLength; i++) {
                            uint256 entryOffset = offset;

                            if (entryOffset + 2 <= xDataLength) {
                                // Read possiblePlaceholder (2 bytes)
                                uint16 possiblePlaceholder;
                                assembly {
                                    let byte1 := byte(0, calldataload(add(xData.offset, entryOffset)))
                                    let byte2 := byte(0, calldataload(add(xData.offset, add(entryOffset, 1))))
                                    possiblePlaceholder := or(shl(8, byte1), byte2)
                                }

                                if (possiblePlaceholder == XC_MARKER) {
                                    // It's a placeholder
                                    xElems.hashList[i] = bytes32(uint256(XC_MARKER) << 240);
                                    offset += PLACEHOLDER_LENGTH; // 2 bytes
                                } else if (entryOffset + HASH_LENGTH <= xDataLength) {
                                    // It's a hash (32 bytes)
                                    bytes32 hashEntry;
                                    assembly {
                                        hashEntry := calldataload(add(xData.offset, entryOffset))
                                    }
                                    xElems.hashList[i] = hashEntry;
                                    offset += HASH_LENGTH; // 32 bytes
                                } else {
                                    // Not enough data for hash
                                    parsingFailed = true;
                                    break;
                                }
                            } else {
                                // Not enough data for placeholder
                                parsingFailed = true;
                                break;
                            }
                        }

                        // Ensure all data is consumed and no extra data remains
                        if (parsingFailed || offset != xDataLength) {
                            xElems.opType = XChainLib.OpType.Conventional;
                        }
                    } else {
                        // Invalid hashListLength
                        xElems.opType = XChainLib.OpType.Conventional;
                    }
                } else {
                    // Not enough data for callData and hashList
                    xElems.opType = XChainLib.OpType.Conventional;
                }
            }
        }
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
        // Replace placeholder with initialOpHash
        bytes32 placeholder = bytes32(uint256(XC_MARKER) << 240);
        if (hashCount > 1) {
            if (hashList[0] == placeholder) {
                hashList[0] = initialOpHash;
            } else if (hashList[1] == placeholder) {
                hashList[1] = initialOpHash;
            } else if (hashCount == MAX_OP_COUNT && hashList[2] == placeholder) {
                hashList[2] = initialOpHash;
            }
        }

        // Compute combined hash
        if (hashCount == MIN_OP_COUNT) {
            return keccak256(abi.encodePacked(hashList[0], hashList[1]));
        } else if (hashCount == MAX_OP_COUNT) {
            return keccak256(abi.encodePacked(hashList[0], hashList[1], hashList[2]));
        } else {
            // For hashCount == 1 or default case use the single hash
            return initialOpHash;
        }
    }
}
