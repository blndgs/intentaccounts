// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@account-abstraction/samples/SimpleAccount.sol";
import "./IntentUserOperation.sol";
import "@account-abstraction/interfaces/IEntryPoint.sol";
import "./XChainLib.sol";

/**
 * minimal account.
 *  this is sample minimal account.
 *  has execute, eth handling methods
 *  has a single signer that can send requests through the entryPoint.
 */
contract IntentSimpleAccount is SimpleAccount {
    using IntentUserOperationLib for UserOperation;
    using ECDSA for bytes32;

    uint256 private constant SIGNATURE_LENGTH = 65;

    constructor(IEntryPoint anEntryPoint) SimpleAccount(anEntryPoint) {}

    function initialize(address anOwner) public virtual override initializer {
        super.initialize(anOwner);
    }

    /**
     * @notice Expose _getUserOpHash
     * @param userOp The UserOperation to hash.
     * @param chainID The chain ID for the operation.
     * @return The computed hash.
     */
    function getUserOpHash(UserOperation calldata userOp, uint256 chainID) external view returns (bytes32) {
        return _getUserOpHash(userOp, chainID);
    }

    function _getUserOpHash(UserOperation calldata userOp, uint256 chainID) internal view returns (bytes32) {
        XChainLib.UserOpType opType = XChainLib.identifyUserOpType(userOp.callData);
    
        bytes32 callDataHash = _getCallDataHash(userOp, opType);
        
        bytes32 opHash = userOp.hashIntentOp(callDataHash);
        
        if (opType == XChainLib.UserOpType.CrossChain) {
            (, bytes32 otherChainHash) = XChainLib.extractChainIdHash(userOp.callData);
    
            // Combine hashes using XOR for symmetry
            opHash = opHash ^ otherChainHash;
        }
        
        return keccak256(abi.encode(opHash, address(entryPoint()), chainID));
    }
    
    function _getCallDataHash(UserOperation calldata userOp, XChainLib.UserOpType opType) internal pure returns (bytes32 callDataHash) {
        uint256 sigLength = userOp.signature.length;

        if (sigLength > SIGNATURE_LENGTH) {
            // There is an intent JSON at the end of the signature,
            // include the remaining part of signature > 65 (ECDSA len) to hashing
            return keccak256(userOp.signature[SIGNATURE_LENGTH:]);
        }

        if (opType == XChainLib.UserOpType.Conventional) {
            return keccak256(userOp.callData);
        } else {
            // Cross-chain UserOp
            bytes calldata callData = XChainLib.extractCallData(userOp.callData);
            return keccak256(callData);
        }
    }

    /**
     * @notice Validates the signature of a UserOperation.
     * @param userOp The UserOperation to validate.
     * @param hash The hash of the UserOperation (unused).
     * @return validationData An error code or zero if validation succeeds.
     */
    function validateSignature(UserOperation calldata userOp, bytes32 hash) external returns (uint256) {
        return _validateSignature(userOp, hash);
    }

    /// @notice Internal method to validate the signature of a UserOperation.
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
     * @notice Executes a batch of calls with specified values.
     *         The first call can be cross-chain; subsequent calls are treated as conventional.
     * @param values The values (Ether amounts) to send with each call.
     * @param dest The destination addresses for each call.
     * @param func The function data (call data) for each call.
     */
    function execValueBatch(uint256[] calldata values, address[] calldata dest, bytes[] calldata func) public {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");
        require(dest.length > 0, "empty batch");

        XChainLib.UserOpType opType = XChainLib.identifyUserOpType(func[0]);

        if (opType == XChainLib.UserOpType.CrossChain) {
            // Process the first function as cross-chain
            bytes calldata extractedCallData = XChainLib.extractCallData(func[0]);
            _call(dest[0], values[0], extractedCallData);
            // Process the rest as conventional
            for (uint256 i = 1; i < dest.length; i++) {
                _call(dest[i], values[i], func[i]);
            }
        } else {
            // All functions are conventional
            for (uint256 i = 0; i < dest.length; i++) {
                _call(dest[i], values[i], func[i]);
            }
        }
    }

    /**
     * @notice Executes a cross-chain call.
     * @param func The function data (call data) to execute.
     * @param value The Ether value to send with the call.
     * @param dest The destination address for the call.
     */
    function xChainCall(bytes calldata func, uint256 value, address dest) external {
        _requireFromEntryPointOrOwner();
        XChainLib.UserOpType opType = XChainLib.identifyUserOpType(func);
        if (opType == XChainLib.UserOpType.Conventional) {
            _call(dest, value, func);
        } else {
            bytes calldata extractedCallData = XChainLib.extractCallData(func);
            _call(dest, value, extractedCallData);
        }
    }
}
