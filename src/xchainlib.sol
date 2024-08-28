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
    }
}
