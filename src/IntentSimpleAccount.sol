// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@account-abstraction/samples/SimpleAccount.sol";
import "./IntentUserOperation.sol";
import "@account-abstraction/interfaces/IEntryPoint.sol";
import "./xchainlib.sol";

/**
 * @title IntentSimpleAccount
 * @dev An extended SimpleAccount that supports intent-based and cross-chain operations.
 * This contract implements ERC-4337 account abstraction with additional features for
 * handling intents and cross-chain transactions.
 */
contract IntentSimpleAccount is SimpleAccount {
    using IntentUserOperationLib for UserOperation;
    using ECDSA for bytes32;

    uint256 internal constant MAX_INTENT_OPS = 3;
    uint256 internal constant PLACEHOLDER = 0xFFFF;
    uint256 private constant SIGNATURE_LENGTH = 65;
    uint256 private constant CALLDATA_LENGTH_SIZE = 2;
    uint256 private constant HASH_LENGTH = 32;
    uint256 private constant OPTYPE_LENGTH = 2;
    uint16 internal constant XC_MARKER = 0xFFFF;
    uint256 private constant PLACEHOLDER_LENGTH = 2;
    uint256 private constant HASHLIST_LENGTH_SIZE = 1;
    uint256 internal constant MIN_HASH_COUNT = 2;
    uint256 internal constant MAX_HASH_COUNT = 3;

    constructor(IEntryPoint anEntryPoint) SimpleAccount(anEntryPoint) {}

    function initialize(address anOwner) public virtual override initializer {
        super.initialize(anOwner);
    }

    /**
     * @dev Expose _getUserOpHash
     * @param userOp The UserOperation to hash.
     * @param chainId The chain Id for the operation.
     * @return The computed hash.
     */
    function getUserOpHash(UserOperation calldata userOp, uint256 chainId) external view returns (bytes32) {
        return _getUserOpHash(userOp, chainId);
    }

    /// Struct to hold parsed data from extraData
    struct ParsedExtraData {
        XChainLib.OpType opType;
        bytes32 callDataHash;
        bytes32[3] hashList;
        uint256 hashCount;
    }

    /// Parses the extraData to extract cross-chain operation information
    /// @param extraData The extra data appended to the signature
    /// @return parsedData A struct containing the parsed information
    function _parseExtraData(bytes calldata extraData) internal pure returns (ParsedExtraData memory parsedData) {
        // Initialize with default values
        parsedData.opType = XChainLib.OpType.Conventional;
        parsedData.hashCount = 0;

        uint256 extraDataLength = extraData.length;
        uint256 offset = 0;

        // Check if extraData has minimum required length
        if (extraDataLength >= OPTYPE_LENGTH + CALLDATA_LENGTH_SIZE + HASHLIST_LENGTH_SIZE + PLACEHOLDER_LENGTH) {
            assembly {
                // Read the marker (2 bytes)
                let marker := shr(240, calldataload(add(extraData.offset, offset)))
                offset := add(offset, OPTYPE_LENGTH)

                // Check if marker indicates cross-chain operation
                switch eq(marker, XC_MARKER)
                case 1 {
                    // If marker matches XC_MARKER
                    // Set opType to CrossChain
                    mstore(add(parsedData, 32), 1)

                    // Read callDataLength (2 bytes)
                    let callDataLength := shr(240, calldataload(add(extraData.offset, offset)))
                    offset := add(offset, CALLDATA_LENGTH_SIZE)

                    // Check if there is enough data
                    switch lt(
                        extraDataLength, add(offset, add(callDataLength, add(HASHLIST_LENGTH_SIZE, PLACEHOLDER_LENGTH)))
                    )
                    case 1 {
                        // If not enough data
                        // Set opType back to Conventional
                        mstore(add(parsedData, 32), 0)
                    }
                    default {
                        // If enough data
                        // Extract callDataHash
                        let callDataStart := add(extraData.offset, offset)
                        mstore(add(parsedData, 64), keccak256(callDataStart, callDataLength))
                        offset := add(offset, callDataLength)

                        // Read hashListLength
                        let hashListLength := byte(0, calldataload(add(extraData.offset, offset)))
                        offset := add(offset, HASHLIST_LENGTH_SIZE)

                        // Validate hashListLength
                        switch or(lt(hashListLength, MIN_HASH_COUNT), gt(hashListLength, MAX_HASH_COUNT))
                        case 1 {
                            // If hashListLength is invalid
                            // Set opType back to Conventional
                            mstore(add(parsedData, 32), 0)
                        }
                        default {
                            // If hashListLength is valid
                            // Store hashCount
                            mstore(add(parsedData, 160), hashListLength)
                            let expectedLength :=
                                add(offset, add(PLACEHOLDER_LENGTH, mul(sub(hashListLength, 1), HASH_LENGTH)))
                            // Check if there's enough data for all hashes
                            switch gt(expectedLength, extraDataLength)
                            case 1 {
                                // If not enough data for all hashes
                                // Set opType back to Conventional
                                mstore(add(parsedData, 32), 0)
                            }
                            default {
                                // If enough data for all hashes
                                // Read placeholder
                                let placeholder := shr(240, calldataload(add(extraData.offset, offset)))
                                switch eq(placeholder, XC_MARKER)
                                case 1 {
                                    // If placeholder is valid
                                    // Store placeholder in hashList
                                    mstore(add(parsedData, 96), shl(240, XC_MARKER))
                                    offset := add(offset, PLACEHOLDER_LENGTH)

                                    // Read remaining hashes
                                    for { let i := 1 } lt(i, hashListLength) { i := add(i, 1) } {
                                        let hashEntry := calldataload(add(extraData.offset, offset))
                                        mstore(add(add(parsedData, 96), mul(32, i)), hashEntry)
                                        offset := add(offset, HASH_LENGTH)
                                    }
                                }
                                default {
                                    // If placeholder is invalid
                                    // Set opType back to Conventional
                                    mstore(add(parsedData, 32), 0)
                                }
                            }
                        }
                    }
                }
            }
        }

        // If opType is Conventional, use the entire extraData as callData
        if (parsedData.opType == XChainLib.OpType.Conventional) {
            parsedData.callDataHash = keccak256(extraData);
        }
    }
    function _parseExtraData(bytes calldata extraData) internal pure returns (ParsedExtraData memory parsedData) {
        // Initialize with default values
        parsedData.opType = XChainLib.OpType.Conventional;
        parsedData.hashCount = 0;
    
        uint256 extraDataLength = extraData.length;
    
        if (extraDataLength >= OPTYPE_LENGTH + CALLDATA_LENGTH_SIZE + HASHLIST_LENGTH_SIZE + PLACEHOLDER_LENGTH) {
            uint256 offset = 0;
    
            // Read the marker (2 bytes)
            bytes2 marker = bytes2(extraData[offset:offset + OPTYPE_LENGTH]);
            offset += OPTYPE_LENGTH;
    
            if (uint16(marker) == XC_MARKER) {
                // Set opType to CrossChain
                parsedData.opType = XChainLib.OpType.CrossChain;
    
                // Read callDataLength (2 bytes)
                uint16 callDataLength = uint16(bytes2(extraData[offset:offset + CALLDATA_LENGTH_SIZE]));
                offset += CALLDATA_LENGTH_SIZE;
    
                if (extraDataLength >= offset + callDataLength + HASHLIST_LENGTH_SIZE + PLACEHOLDER_LENGTH) {
                    // Extract callDataHash
                    parsedData.callDataHash = keccak256(extraData[offset:offset + callDataLength]);
                    offset += callDataLength;
    
                    // Read hashListLength
                    uint8 hashListLength = uint8(extraData[offset]);
                    offset += HASHLIST_LENGTH_SIZE;
    
                    if (hashListLength >= MIN_HASH_COUNT && hashListLength <= MAX_HASH_COUNT) {
                        parsedData.hashCount = hashListLength;
    
                        uint256 expectedLength =
                            offset + PLACEHOLDER_LENGTH + (hashListLength - 1) * HASH_LENGTH;
                        if (extraDataLength >= expectedLength) {
                            // Read placeholder
                            bytes2 placeholder = bytes2(extraData[offset:offset + PLACEHOLDER_LENGTH]);
                            if (uint16(placeholder) == XC_MARKER) {
                                // Store placeholder in hashList
                                parsedData.hashList[0] = bytes32(uint256(XC_MARKER) << 240);
                                offset += PLACEHOLDER_LENGTH;
    
                                // Read remaining hashes
                                for (uint256 i = 1; i < hashListLength; i++) {
                                    parsedData.hashList[i] = bytes32(extraData[offset:offset + HASH_LENGTH]);
                                    offset += HASH_LENGTH;
                                }
                            } else {
                                // If placeholder is invalid, set opType back to Conventional
                                parsedData.opType = XChainLib.OpType.Conventional;
                            }
                        } else {
                            // If not enough data for all hashes, set opType back to Conventional
                            parsedData.opType = XChainLib.OpType.Conventional;
                        }
                    } else {
                        // If hashListLength is invalid, set opType back to Conventional
                        parsedData.opType = XChainLib.OpType.Conventional;
                    }
                } else {
                    // If not enough data, set opType back to Conventional
                    parsedData.opType = XChainLib.OpType.Conventional;
                }
            }
        }
    
        // Do NOT set callDataHash for conventional operations here
    }

    /// Computes the hash for a UserOperation, handling both cross-chain and conventional operations
    /// @param userOp The UserOperation to process
    /// @return opHash The computed operation hash
    function _getUserOpHash(UserOperation calldata userOp, uint256 chainId) internal view returns (bytes32 opHash) {
        // Extract extraData from the signature if present
        bytes calldata extraData = userOp.signature.length > SIGNATURE_LENGTH
            ? userOp.signature[SIGNATURE_LENGTH:]
            : userOp.signature[userOp.signature.length : userOp.signature.length];
    
        // Parse the extraData
        ParsedExtraData memory parsedData = _parseExtraData(extraData);
    
        // Compute callDataHash for conventional operations
        if (parsedData.opType == XChainLib.OpType.Conventional) {
            if (extraData.length > 0) {
                // Use extraData as the callDataHash
                parsedData.callDataHash = keccak256(extraData);
            } else {
                parsedData.callDataHash = keccak256(userOp.callData);
            }
        }
    
        // Compute the initial opHash
        opHash = keccak256(
            abi.encode(
                userOp.hashIntentOp(parsedData.callDataHash),
                address(entryPoint()),
                chainId
            )
        );
    
        // For cross-chain operations, compute the combined hash
        if (parsedData.opType == XChainLib.OpType.CrossChain && parsedData.hashCount > 0) {
            opHash = _computeCrossChainHash(opHash, parsedData.hashList, parsedData.hashCount);
        }
    
        return opHash;
    }

    /// Computes the final hash for cross-chain operations
    /// @param initialOpHash The initial operation hash
    /// @param hashList Array of hashes including the placeholder
    /// @param hashCount Number of valid hashes in the hashList
    /// @return The computed cross-chain hash
    function _computeCrossChainHash(bytes32 initialOpHash, bytes32[3] memory hashList, uint256 hashCount)
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
        if (hashCount == 2) {
            return keccak256(abi.encodePacked(hashList[0], hashList[1]));
        } else if (hashCount == 3) {
            return keccak256(abi.encodePacked(hashList[0], hashList[1], hashList[2]));
        } else {
            // For hashCount == 1, use the single hash
            return keccak256(abi.encodePacked(hashList[0]));
        }
    }

    /**
     * @dev Validates the signature of a UserOperation.
     * @param userOp The UserOperation to validate.
     * @return validationData An error code or zero if validation succeeds.
     */
    function validateSignature(UserOperation calldata userOp, bytes32) external returns (uint256) {
        return _validateSignature(userOp, bytes32(0));
    }

    /// @dev Internal method to validate the signature of a UserOperation.
    function _validateSignature(UserOperation calldata userOp, bytes32)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        bytes32 userOpHash = _getUserOpHash(userOp, block.chainid);
        bytes32 ethHash = userOpHash.toEthSignedMessageHash();

        // Extract the first 65 bytes of the signature
        bytes memory signature65 = userOp.signature[:SIGNATURE_LENGTH];
        if (owner != ethHash.recover(signature65)) {
            return SIG_VALIDATION_FAILED;
        }
        return 0; // Signature is valid
    }

    /**
     * @dev Executes a batch of calls with specified values.
     * @param values The values (Ether amounts) to send with each call.
     * @param dest The destination addresses for each call.
     * @param func The function data (call data) for each call.
     */
    function execValueBatch(uint256[] calldata values, address[] calldata dest, bytes[] calldata func) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");

        uint256 len = dest.length;
        for (uint256 i = 0; i < len;) {
            _call(dest[i], values[i], func[i]);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Executes a single call.
     * @param value The Ether value to send with the call.
     * @param dest The destination address for the call.
     * @param func The function data (call data) to execute.
     */
    function xCall(uint256 value, address dest, bytes calldata func) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }
}
