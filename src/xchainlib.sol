// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

/**
 * @title XChainLib
 * @dev Library for handling cross-chain UserOperations in ERC-4337 compatible wallets with packed callData
 */
library XChainLib {
    uint256 private constant CALLDATA_LENGTH_SIZE = 2;
    uint256 private constant HASH_LENGTH = 32;
    uint256 private constant OPTYPE_LENGTH = 2;
    uint16 internal constant XC_MARKER = 0xFFFF;
    uint256 private constant PLACEHOLDER_LENGTH = 2;
    uint256 private constant HASHLIST_LENGTH_SIZE = 1;
    uint256 internal constant MIN_HASH_COUNT = 2;
    uint256 internal constant MAX_HASH_COUNT = 3;

    enum OpType {
        Conventional,
        CrossChain
    }

    // Custom errors
    error InvalidCallDataLength(uint256 length);

    /**
     * @dev Identifies the type of UserOperation based on the call data.
     * @param callData The call data of the UserOperation.
     * @return The UserOperation type (Conventional or CrossChain).
     *
     * X-chain calldata format:
     * [2 bytes opType (0xFFFF)] + [2 bytes callDataLength] + [callData] + [2 bytes hashList length] +[hashListEntries]
     *
     * Each hash list entry is either:
     * - 2 bytes (placeholder 0xFFFF)
     * - 32 bytes (hash)
     */
    function identifyUserOpType(bytes calldata callData) public pure returns (OpType) {
        if (callData.length >= OPTYPE_LENGTH + CALLDATA_LENGTH_SIZE + HASHLIST_LENGTH_SIZE + PLACEHOLDER_LENGTH) {
            uint256 offset = 0;
            uint16 marker;
            assembly {
                marker := shr(240, calldataload(add(callData.offset, offset)))
            }
            offset += OPTYPE_LENGTH;

            if (marker == XC_MARKER) {
                // Read callDataLength
                uint16 callDataLength;
                assembly {
                    callDataLength := shr(240, calldataload(add(callData.offset, offset)))
                }
                offset += CALLDATA_LENGTH_SIZE;

                // Check if there is enough data for callData and hash list
                if (callData.length >= offset + callDataLength + HASHLIST_LENGTH_SIZE + PLACEHOLDER_LENGTH) {
                    offset += callDataLength;

                    // Read hashListLength
                    uint8 hashListLength;
                    assembly {
                        hashListLength := calldataload(add(callData.offset, offset))
                    }
                    offset += HASHLIST_LENGTH_SIZE;

                    if (hashListLength >= MIN_HASH_COUNT && hashListLength <= MAX_HASH_COUNT) {
                        // Calculate expected total length
                        uint256 expectedLength = offset + PLACEHOLDER_LENGTH + (hashListLength - 1) * HASH_LENGTH;
                        if (callData.length == expectedLength) {
                            return OpType.CrossChain;
                        }
                    }
                }
            }
        }
        return OpType.Conventional;
    }

    /**
     * @dev Extracts the call data from a cross-chain UserOperation.
     * @param callData The call data containing the embedded call data.
     * @return The extracted call data.
     */
    function extractCallData(bytes calldata callData) internal pure returns (bytes calldata) {
        if (callData.length < OPTYPE_LENGTH + CALLDATA_LENGTH_SIZE + HASH_LENGTH) {
            revert InvalidCallDataLength(callData.length);
        }

        uint256 offset = OPTYPE_LENGTH; // opType (2 bytes)

        // read calldataLength directly from calldata without
        // copying to memory
        uint16 calldataLength;
        assembly {
            let ptr := add(callData.offset, offset)
            calldataLength := shr(240, calldataload(ptr))
        }
        offset += CALLDATA_LENGTH_SIZE;

        if (callData.length != offset + calldataLength + HASH_LENGTH) {
            revert InvalidCallDataLength(callData.length);
        }

        return callData[offset:offset + calldataLength];
    }

    /**
     * @dev Extracts the chain ID and the other chain's hash from the call data.
     * @param callData The call data containing the chain ID and other chain's hash.
     * @return otherChainHash The extracted hash of the other chain's operation.
     */
    function extractHash(bytes calldata callData) internal pure returns (bytes32 otherChainHash) {
        if (callData.length < OPTYPE_LENGTH + CALLDATA_LENGTH_SIZE + HASH_LENGTH) {
            revert InvalidCallDataLength(callData.length);
        }

        otherChainHash = bytes32(callData[callData.length - HASH_LENGTH:callData.length]);
    }
}
