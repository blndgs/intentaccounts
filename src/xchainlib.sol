// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./IntentUserOperation.sol";
import {console2} from "forge-std/console2.sol";

/**
 * @title CrossChainUserOpLib
 * @dev Library for handling cross-chain UserOperations in ERC-4337 compatible wallets
 */
library XChainUserOpLib {
    // Maximum allowed calldata length for a UserOperation (4KB)
    uint256 internal constant MAX_CALLDATA_LENGTH = 4098; // 2 bytes (length) + 4096 bytes for 2x userOp callData
    uint256 internal constant MAX_OP_LENGTH = 2048;

    /**
     * @dev Packed structure for efficient UserOperation storage and transfer
     */
    struct PackedUserOp {
        uint256 nonce;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes callData;
    }

    /**
     * @dev Checks if a UserOperation's callData belongs to a cross-chain operation
     * @param userOp The UserOperation to check
     * @return bool True if it's a cross-chain operation, false otherwise
     */
    function isCrossChainUserOp(bytes calldata callData) internal pure returns (bool) {
        if (callData.length <= 2) return false;
        uint16 length = uint16(bytes2(callData[:2]));
        return length > 0 && length < callData.length && length <= MAX_OP_LENGTH;
    }

    /**
     * @dev Validates the length of `userOp.callData` to be less than or equal to `MAX_CALLDATA_LENGTH`.
     * @param userOp The UserOperation whose calldata length is to be validated.
     * @notice This function will revert if the calldata length exceeds the maximum allowed length.
     */
    function validateCalldataLength(UserOperation calldata userOp) internal pure {
        require(userOp.callData.length <= MAX_CALLDATA_LENGTH, "Calldata exceeds maximum length");
    }

    /**
     * @dev Extracts the destination UserOperation from a combined UserOperation
     * @param combinedOp The combined UserOperation containing both source and destination data
     * @return The extracted destination UserOperation
     */
    function extractDestUserOp(UserOperation calldata combinedOp) internal pure returns (UserOperation memory) {
        require(isCrossChainUserOp(combinedOp), "Not a cross-chain UserOp");
        bytes memory packedDestOpData = extractPackedData(combinedOp.callData);
        PackedUserOp memory packedDestOp = decodePackedUserOp(packedDestOpData);
        return unpackUserOp(packedDestOp, combinedOp.sender);
    }

    /**
     * @dev Extracts the packed destination UserOperation serialized data from the combined callData
     * @param callData The combined callData containing both source and destination data
     * @return packedDestOpData The packed destination UserOperation data
     */
    function extractPackedData(bytes calldata callData) private pure returns (bytes memory) {
        uint16 sourceCallDataLength = uint16(bytes2(callData[:2]));
        require(callData.length > 2 + sourceCallDataLength, "Invalid callData format");
        bytes memory packedDestOpData = callData[2 + sourceCallDataLength:];
        require(packedDestOpData.length > 0, "No packed destination UserOp found");
        return packedDestOpData;
    }

    function decodePackedUserOp(bytes memory packedDestOpData) private pure returns (PackedUserOp memory) {
        PackedUserOp memory packedDestOp = abi.decode(packedDestOpData, (PackedUserOp));

        return packedDestOp;
    }

    function unpackUserOp(PackedUserOp memory packedOp, address sender) internal pure returns (UserOperation memory) {
        return UserOperation({
            sender: sender,
            nonce: packedOp.nonce,
            initCode: new bytes(0),
            callData: packedOp.callData,
            callGasLimit: packedOp.callGasLimit,
            verificationGasLimit: packedOp.verificationGasLimit,
            preVerificationGas: packedOp.preVerificationGas,
            maxFeePerGas: packedOp.maxFeePerGas,
            maxPriorityFeePerGas: packedOp.maxPriorityFeePerGas,
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });
    }
}
