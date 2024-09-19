// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

/**
 * @title XChainLib
 * @dev Library for handling cross-chain UserOperations in ERC-4337 compatible wallets with packed callData
 */
library XChainLib {
    uint256 internal constant MAX_COMBINED_CALLDATA_LENGTH = 40960; // MAX_CALLDATA_LENGTH * 4
    uint256 internal constant MAX_CALLDATA_LENGTH = 10240;
    uint256 internal constant MAX_CALLDATA_COUNT = 4;
    uint256 internal constant MAX_CHAIN_ID = 0xFFFF;
    uint256 private constant CHAINID_LENGTH = 2;
    uint256 private constant CALLDATA_LENGTH_SIZE = 2;
    uint256 private constant HASH_LENGTH = 32;
    uint256 private constant OPTYPE_LENGTH = 2;
    uint16 private constant XC_MARKER = 0xFFFF;

    enum OpType {
        Conventional,
        CrossChain
    }

    // Custom errors
    error InvalidCallDataLength(uint256 length);
    error InvalidEncodedData();
    error InvalidNumberOfCallData(uint256 count);
    error ChainDataTooShort();
    error ZeroChainId();
    error InvalidUserOpType(uint16 opType);

    /**
     * @notice Identifies the type of UserOperation based on the call data.
     * @param callData The call data of the UserOperation.
     * @return The UserOperation type (Conventional or CrossChain).
     * X-chain calldata format:
     * [2 bytes opType (0xFFFF)] + [2 bytes chainId] + [2 bytes calldataLength] + [callData] + [32 bytes otherChainHash]
     */
    function identifyUserOpType(bytes calldata callData) public pure returns (OpType) {
        uint256 minCrossChainLength = OPTYPE_LENGTH + CHAINID_LENGTH + CALLDATA_LENGTH_SIZE + HASH_LENGTH;

        if (callData.length >= minCrossChainLength) {
            uint16 opType;
            assembly {
                opType := shr(240, calldataload(callData.offset))
            }
            if (opType == 0xFFFF) {
                // Potentially a cross-chain UserOp, validate further
                uint256 offset = OPTYPE_LENGTH + CHAINID_LENGTH;
                if (callData.length >= offset + CALLDATA_LENGTH_SIZE) {
                    // read calldataLength directly from calldata without
                    // copying to memory
                    uint16 calldataLength;
                    assembly {
                        let ptr := add(callData.offset, offset)
                        calldataLength := shr(240, calldataload(ptr))
                    }
                    offset += CALLDATA_LENGTH_SIZE;
                    uint256 expectedLength = offset + calldataLength + HASH_LENGTH;
                    if (callData.length == expectedLength) {
                        return OpType.CrossChain;
                    }
                }
            }
        }
        return OpType.Conventional;
    }

    /**
     * @notice Extracts the call data from a cross-chain UserOperation.
     * @param callData The call data containing the embedded call data.
     * @return The extracted call data.
     */
    function extractCallData(bytes calldata callData) internal pure returns (bytes calldata) {
        if (callData.length < OPTYPE_LENGTH + CHAINID_LENGTH + CALLDATA_LENGTH_SIZE + HASH_LENGTH) {
            revert InvalidCallDataLength(callData.length);
        }

        uint256 offset = OPTYPE_LENGTH + CHAINID_LENGTH; // opType (2 bytes) + chainId (2 bytes)

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
     * @notice Extracts the chain ID and the other chain's hash from the call data.
     * @param callData The call data containing the chain ID and other chain's hash.
     * @return otherChainHash The extracted hash of the other chain's operation.
     */
    function extractHash(bytes calldata callData)
        internal
        pure
        returns (bytes32 otherChainHash)
    {
        if (callData.length < OPTYPE_LENGTH + CHAINID_LENGTH + CALLDATA_LENGTH_SIZE + HASH_LENGTH) {
            revert InvalidCallDataLength(callData.length);
        }

        otherChainHash = bytes32(callData[callData.length - HASH_LENGTH:callData.length]);
    }
}
