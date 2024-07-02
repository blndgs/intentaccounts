// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {IKernelValidator} from "../lib/kernel/src/interfaces/IKernelValidator.sol";
import {ValidationData} from "../lib/kernel/src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "../lib/kernel/src/common/Constants.sol";

address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

struct ECDSAValidatorStorage {
    address owner;
}
// ref https://github.com/zerodevapp/kernel/blob/v2.4/src/interfaces/IKernelValidator.sol
// modes:
// 1. default mode, use preset validator for the kernel
// 2. enable mode, enable a new validator for given action and use it for current userOp
// 3. sudo mode, use default plugin for current userOp

contract KernelIntentValidator is IKernelValidator {
    // Custom errors
    error EndLessThanStart();
    error EndOutOfBounds(uint256 dataLength, uint256 end);
    error StartOutOfBounds(uint256 dataLength, uint256 start);

    event OwnerChanged(address indexed kernel, address indexed oldOwner, address indexed newOwner);

    mapping(address => ECDSAValidatorStorage) public ecdsaValidatorStorage;

    function disable(bytes calldata) external payable override {
        delete ecdsaValidatorStorage[msg.sender];
    }

    function enable(bytes calldata _data) external payable override {
        address owner = address(bytes20(_data[0:20]));
        address oldOwner = ecdsaValidatorStorage[msg.sender].owner;
        ecdsaValidatorStorage[msg.sender].owner = owner;
        emit OwnerChanged(msg.sender, oldOwner, owner);
    }

    /**
     * @dev Expose _slice for testing
     */
    function slice(bytes memory data, uint256 start, uint256 end) external pure returns (bytes memory result) {
        return _slice(data, start, end);
    }

    /**
     * @dev Slices a bytes array to return a portion specified by the start and end indices.
     * @param data The bytes array to be sliced.
     * @param start The index in the bytes array where the slice begins.
     * @param end The index in the bytes array where the slice ends (exclusive).
     * @return result The sliced portion of the bytes array.
     * Note: The function reverts if the start index is not less than the end index,
     *       if start or end is out of the bounds of the data array.
     */
    function _slice(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory result) {
        if (end <= start) revert EndLessThanStart();
        if (end > data.length) revert EndOutOfBounds(data.length, end);
        if (start >= data.length) revert StartOutOfBounds(data.length, start);

        assembly {
            // Allocate memory for the result
            result := mload(0x40)
            mstore(result, sub(end, start)) // Set the length of the result
            let resultPtr := add(result, 0x20)

            // Copy the data from the start to the end
            for { let i := start } lt(i, end) { i := add(i, 0x20) } {
                let dataPtr := add(add(data, 0x20), i)
                mstore(add(resultPtr, sub(i, start)), mload(dataPtr))
            }

            // Update the free memory pointer
            mstore(0x40, add(resultPtr, sub(end, start)))
        }
    }

    uint256 private constant SIGNATURE_LENGTH = 65;

    function getUserOpHash(UserOperation calldata userOp, uint256 chainID) public pure returns (bytes32) {
        bytes32 callData = calldataKeccak(userOp.callData);

        uint256 sigLength = userOp.signature.length;

        if (sigLength > SIGNATURE_LENGTH) {
            // There is an intent JSON at the end of the signature,
            // include the remaining part of signature > 65 (intent json) for hashing
            callData = calldataKeccak(userOp.signature[SIGNATURE_LENGTH:]);
        }

        return keccak256(abi.encode(hashIntentOp(userOp, callData), ENTRYPOINT_V06, chainID));
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32, uint256)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        bytes32 _userOpHash = getUserOpHash(_userOp, block.chainid);
        address owner = ecdsaValidatorStorage[_userOp.sender].owner;
        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);

        // Extract the first 65 bytes of the signature
        bytes memory signature65 = _userOp.signature[:SIGNATURE_LENGTH];

        if (owner == ECDSA.recover(hash, signature65)) {
            return ValidationData.wrap(0);
        }

        return SIG_VALIDATION_FAILED;
    }

    function validateSignature(bytes32 hash, bytes calldata signature) public view override returns (ValidationData) {
        address owner = ecdsaValidatorStorage[msg.sender].owner;

        // Extract the first 65 bytes of the signature
        bytes memory signature65 = signature[:SIGNATURE_LENGTH];

        address recovered = ECDSA.recover(hash, signature65);
        if (owner == ECDSA.recover(hash, signature65)) {
            return ValidationData.wrap(0);
        }

        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        recovered = ECDSA.recover(ethHash, signature65);
        if (owner != recovered) {
            return SIG_VALIDATION_FAILED;
        }
        return ValidationData.wrap(0);
    }

    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        return ecdsaValidatorStorage[msg.sender].owner == _caller;
    }

    function hashIntentOp(UserOperation calldata userOp, bytes32 hashedCD) internal pure returns (bytes32) {
        return keccak256(packIntentOp(userOp, hashedCD));
    }

    function packIntentOp(UserOperation calldata userOp, bytes32 hashedCD)
        internal
        pure
        returns (bytes memory ret)
    {
        address sender = getSender(userOp);
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
        uint256 callGasLimit = userOp.callGasLimit;
        uint256 verificationGasLimit = userOp.verificationGasLimit;
        uint256 preVerificationGas = userOp.preVerificationGas;
        uint256 maxFeePerGas = userOp.maxFeePerGas;
        uint256 maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
        bytes32 hashPaymasterAndData = calldataKeccak(userOp.paymasterAndData);

        return abi.encode(
            sender,
            nonce,
            hashInitCode,
            hashedCD,
            callGasLimit,
            verificationGasLimit,
            preVerificationGas,
            maxFeePerGas,
            maxPriorityFeePerGas,
            hashPaymasterAndData
        );
    }

    function getSender(UserOperation calldata userOp) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {
            data := calldataload(userOp)
        }
        return address(uint160(data));
    }

    /**
     * keccak function over memory.
     * @dev directly use memory data for keccak.
     */
    function memoryKeccak(bytes memory data) private pure returns (bytes32 ret) {
        assembly {
            // First 32 bytes of the bytes array 'data' stores the length of the data
            let len := mload(data) // Load the length of the data
            let dataPtr := add(data, 0x20) // Skip the first 32 bytes where the length is stored

            // Perform the keccak hash on the memory data
            ret := keccak256(dataPtr, len)
        }
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
