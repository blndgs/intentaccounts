// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {IKernelValidator} from "../lib/kernel/src/interfaces/IKernelValidator.sol";
import {ValidationData} from "../lib/kernel/src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "../lib/kernel/src/common/Constants.sol";

// ref https://github.com/zerodevapp/kernel/blob/v2.4/src/interfaces/IKernelValidator.sol
// modes:
// 1. default mode, use preset validator for the kernel
// 2. enable mode, enable a new validator for given action and use it for current userOp
// 3. sudo mode, use default plugin for current userOp

import {XChainLib} from "./xchainlib.sol";

/**
 * @title KernelIntentValidator
 * @dev A validator module for Kernel accounts that supports both conventional and cross-chain intent validation.
 * This validator extends the basic ECDSA validation with cross-chain capabilities by implementing hash linking
 * between operations on different chains.
 */
contract KernelIntentValidator is IKernelValidator {
    using ECDSA for bytes32;

    event OwnerChanged(address indexed kernel, address indexed oldOwner, address indexed newOwner);

    // Storage for owner addresses of Kernel accounts
    mapping(address => ECDSAValidatorStorage) public ecdsaValidatorStorage;

    // Constants
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 private constant SIGNATURE_LENGTH = 65;

    // Storage struct for owner address
    struct ECDSAValidatorStorage {
        address owner;
    }

    /**
     * @dev Disables the validator by removing the owner address
     */
    function disable(bytes calldata) external payable override {
        delete ecdsaValidatorStorage[msg.sender];
    }

    /**
     * @dev Enables the validator by setting the owner address
     * @param _data The owner address encoded as bytes
     */
    function enable(bytes calldata _data) external payable override {
        // Protect against accidental ETH transfers
        require(msg.value == 0, "ETH transfers not supported");

        address owner = address(bytes20(_data[0:20]));
        address oldOwner = ecdsaValidatorStorage[msg.sender].owner;
        ecdsaValidatorStorage[msg.sender].owner = owner;
        emit OwnerChanged(msg.sender, oldOwner, owner);
    }

    /**
     * @dev Computes the UserOperation hash, handling both conventional and cross-chain operations
     * @param userOp The UserOperation to process
     * @param chainID The chain ID where the operation is being executed
     * @return opHash The computed operation hash
     */
    function getUserOpHash(UserOperation calldata userOp, uint256 chainID) public pure returns (bytes32 opHash) {
        // Extract xData from signature if present (post ECDSA signature)
        bytes calldata xData =
            userOp.signature.length > SIGNATURE_LENGTH ? userOp.signature[SIGNATURE_LENGTH:] : userOp.signature[0:0];

        // Parse the cross-chain data structure
        XChainLib.xCallData memory parsedData = XChainLib.parseXElems(xData);

        // Handle callData hash computation per operation type
        if (parsedData.opType == XChainLib.OpType.Conventional) {
            if (xData.length > 0) {
                // Intent operation: use post-signature data as callData hash
                parsedData.callDataHash = keccak256(xData);
            } else {
                // Vanilla operation: use original callData
                parsedData.callDataHash = calldataKeccak(userOp.callData);
            }
        }

        // Compute the initial operation hash
        opHash = keccak256(abi.encode(hashIntentOp(userOp, parsedData.callDataHash), ENTRYPOINT_V06, chainID));

        // For cross-chain operations, compute the combined hash with other chain operations
        if (parsedData.opType == XChainLib.OpType.CrossChain) {
            opHash = XChainLib.computeCrossChainHash(opHash, parsedData.hashList, parsedData.hashCount);
        }

        return opHash;
    }

    /**
     * @dev Validates a UserOperation signature
     * @param _userOp The UserOperation to validate
     * @return validationData The validation result
     */
    function validateUserOp(UserOperation calldata _userOp, bytes32, uint256)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        bytes32 userOpHash = getUserOpHash(_userOp, block.chainid);
        // Extract the ECDSA signature (first 65 bytes)
        bytes memory signature65 = _userOp.signature[:SIGNATURE_LENGTH];
        return _validateSignature(userOpHash, signature65, _userOp.sender);
    }

    /**
     * @dev Validates a signature against a pre-computed hash
     * @param userOpHash The hash to validate against
     * @param signature The signature to validate
     */
    function validateSignature(bytes32 userOpHash, bytes calldata signature)
        external
        view
        override
        returns (ValidationData)
    {
        bytes memory signature65 = signature[:SIGNATURE_LENGTH];
        return _validateSignature(userOpHash, signature65, msg.sender);
    }

    /**
     * @dev Internal signature validation logic
     * @param hash The hash to validate
     * @param signature65 The 65-byte ECDSA signature
     * @param sender The sender address (Kernel account)
     */
    function _validateSignature(bytes32 hash, bytes memory signature65, address sender)
        internal
        view
        returns (ValidationData)
    {
        address owner = ecdsaValidatorStorage[sender].owner;

        // Try standard ECDSA recovery
        if (owner == hash.recover(signature65)) {
            return ValidationData.wrap(0);
        }

        // Try EIP-191 signed message recovery
        bytes32 ethHash = hash.toEthSignedMessageHash();
        if (owner == ethHash.recover(signature65)) {
            return ValidationData.wrap(0);
        }

        return SIG_VALIDATION_FAILED;
    }

    /**
     * @dev Validates if a caller is authorized
     */
    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        return ecdsaValidatorStorage[msg.sender].owner == _caller;
    }

    /**
     * @dev Computes hash of intent operation
     */
    function hashIntentOp(UserOperation calldata userOp, bytes32 hashedCD) internal pure returns (bytes32) {
        return keccak256(packIntentOp(userOp, hashedCD));
    }

    /**
     * @dev Packs intent operation data for hashing
     */
    function packIntentOp(UserOperation calldata userOp, bytes32 hashedCD) internal pure returns (bytes memory) {
        return abi.encode(
            getSender(userOp),
            userOp.nonce,
            calldataKeccak(userOp.initCode),
            hashedCD,
            userOp.callGasLimit,
            userOp.verificationGasLimit,
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            calldataKeccak(userOp.paymasterAndData)
        );
    }

    /**
     * @dev Extracts sender address from UserOperation calldata
     */
    function getSender(UserOperation calldata userOp) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {
            data := calldataload(userOp)
        }
        return address(uint160(data));
    }

    /**
     * keccak function over calldata.
     * @dev copy calldata into memory, do keccak and drop allocated memory. Strangely, this is more efficient than letting solidity do it.
     */
    function calldataKeccak(bytes calldata data) private pure returns (bytes32 ret) {
        assembly {
            let mem := mload(0x40)
            let len := data.length
            calldatacopy(mem, data.offset, len)
            ret := keccak256(mem, len)
        }
    }
}
