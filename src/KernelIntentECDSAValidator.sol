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
    using ECDSA for bytes32;
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

    /**
     * Generate the hash of the intent operation. We don't trust the incoming hash
     * to be aware of the intent JSON in the signature.
     */
    function validateUserOp(UserOperation calldata _userOp, bytes32, uint256)
    external
    payable
    override
    returns (ValidationData validationData)
    {
        bytes32 _userOpHash = getUserOpHash(_userOp, block.chainid);
        bytes memory signature65 = _userOp.signature[:SIGNATURE_LENGTH];
        return _validateSignature(_userOpHash, signature65, _userOp.sender);
    }

    function validateSignature(bytes32 userOpHash, bytes calldata signature)
    external view override
    returns (ValidationData) {
        bytes memory signature65 = signature[:SIGNATURE_LENGTH];
        return _validateSignature(userOpHash, signature65, msg.sender);
    }

    function _validateSignature(bytes32 hash, bytes memory signature65, address sender) internal view returns (ValidationData) {
        address owner = ecdsaValidatorStorage[sender].owner;

        if (owner == hash.recover(signature65)) {
            return ValidationData.wrap(0);
        }

        bytes32 ethHash = hash.toEthSignedMessageHash();
        if (owner == ethHash.recover(signature65)) {
            return ValidationData.wrap(0);
        }

        return SIG_VALIDATION_FAILED;
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
        returns (bytes memory)
    {
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
