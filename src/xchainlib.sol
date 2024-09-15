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
    uint256 private constant CHAINID_LENGTH = 2;
    uint256 private constant CALLDATA_LENGTH_SIZE = 2;
    uint256 private constant HASH_LENGTH = 32;

    enum UserOpType {
        Conventional,
        CrossChain
    }

    // Custom errors
    error InvalidCallDataLength(uint256 length);
    error InvalidEncodedData();
    error InvalidNumberOfCallData(uint256 count);
    error ChainDataTooShort();
    error ZeroChainId();
    error InvalidUserOpType(uint8 opType);

    function identifyUserOpType(bytes calldata callData) internal pure returns (UserOpType) {
        // Minimum length for cross-chain callData:
        // opType (1) + chainId (2) + calldataLength (2) + otherChainHash (32)
        uint256 minCrossChainLength = 1 + CHAINID_LENGTH + CALLDATA_LENGTH_SIZE + HASH_LENGTH;
        
        if (callData.length >= minCrossChainLength) {
            uint8 opType = uint8(callData[0]);
            if (opType == 1) {
                // Potentially a cross-chain UserOp, validate further
                uint256 offset = 1 + CHAINID_LENGTH;
                if (callData.length >= offset + CALLDATA_LENGTH_SIZE) {
                    uint16 calldataLength = (uint16(uint8(callData[offset])) << 8) | uint8(callData[offset + 1]);
                    offset += CALLDATA_LENGTH_SIZE;
                    // Expected total length
                    uint256 expectedLength = 1 + CHAINID_LENGTH + CALLDATA_LENGTH_SIZE + calldataLength + HASH_LENGTH;
                    if (callData.length == expectedLength) {
                        return UserOpType.CrossChain;
                    }
                }
            }
        }
        return UserOpType.Conventional;
    }

    function extractCallData(bytes calldata callData) internal pure returns (bytes calldata) {
        if (callData.length < 1 + CHAINID_LENGTH + CALLDATA_LENGTH_SIZE + HASH_LENGTH) {
            revert InvalidCallDataLength(callData.length);
        }
        
        uint256 offset = 1 + CHAINID_LENGTH; // opType (1) + chainId (2)

        // read calldataLength directly from calldata without 
        // copying to memory
        // uint16 calldataLength = (uint16(uint8(callData[offset])) << 8) | uint8(callData[offset + 1]);
        uint16 calldataLength;
        assembly {
            let ptr := add(callData.offset, offset)
            calldataLength := shr(240, calldataload(ptr))
        }
        
        offset += CALLDATA_LENGTH_SIZE;
        
        if (callData.length != offset + calldataLength + HASH_LENGTH) {
            revert InvalidCallDataLength(callData.length);
        }
        
        return callData[offset : offset + calldataLength];
    }
    
    function extractChainIdHash(bytes calldata callData) internal pure returns (uint16 chainId, bytes32 otherChainHash) {
        if (callData.length < 1 + CHAINID_LENGTH + CALLDATA_LENGTH_SIZE + HASH_LENGTH) {
            revert InvalidCallDataLength(callData.length);
        }
        
        // Read chainId directly from calldata
        // instead of copying to memory
        // chainId = (uint16(uint8(callData[1])) << 8) | uint8(callData[2]);
        assembly {
            let ptr := add(callData.offset, 1) // Skip opType (1 byte)
            chainId := shr(240, calldataload(ptr))
        }
        
        // The otherChainHash is at the end of the callData
        otherChainHash = bytes32(callData[callData.length - HASH_LENGTH : callData.length]);
    }    
}
