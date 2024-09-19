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
 * @title IntentSimpleAccount
 * @dev An extended SimpleAccount that supports intent-based and cross-chain operations.
 * This contract implements ERC-4337 account abstraction with additional features for
 * handling intents and cross-chain transactions.
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
     * @dev Expose _getUserOpHash
     * @param userOp The UserOperation to hash.
     * @param chainID The chain ID for the operation.
     * @return The computed hash.
     */
    function getUserOpHash(UserOperation calldata userOp, uint256 chainID) external view returns (bytes32) {
        return _getUserOpHash(userOp, chainID);
    }

    /**
     * @dev Internal function to compute the hash of a UserOperation.
     * @param userOp The UserOperation to hash.
     * @param chainID The chain ID for the operation.
     * @return The computed hash of the UserOperation.
     */
    function _getUserOpHash(UserOperation calldata userOp, uint256 chainID) internal view returns (bytes32) {
        (XChainLib.OpType opType, bytes32 callDataHash, bytes32 otherChainHash) = _getCallDataHash(userOp);

        bytes32 opHash = keccak256(abi.encode(userOp.hashIntentOp(callDataHash), address(entryPoint()), chainID));

        if (opType == XChainLib.OpType.CrossChain) {
            opHash ^= otherChainHash;
        }

        return opHash;
    }

    /**
     * @dev Computes the hash of the call data and determines the UserOperation type.
     * @param userOp The UserOperation to process.
     * @return opType The type of the UserOperation (Conventional or CrossChain).
     * @return cdHash The hash of the call data.
     * @return otherChainHash The hash of the other chain's operation (for cross-chain ops).
     */
    function _getCallDataHash(UserOperation calldata userOp)
        internal
        pure
        returns (XChainLib.OpType opType, bytes32 cdHash, bytes32 otherChainHash)
    {
        uint256 sigLength = userOp.signature.length;

        if (sigLength > SIGNATURE_LENGTH) {
            // There is an intent JSON at the end of the signature,
            bytes calldata callDataVal = userOp.signature[SIGNATURE_LENGTH:];
            opType = XChainLib.identifyUserOpType(callDataVal);

            if (opType == XChainLib.OpType.CrossChain) {
                otherChainHash = XChainLib.extractHash(callDataVal);
                cdHash = keccak256(XChainLib.extractCallData(callDataVal));
            } else {
                cdHash = keccak256(callDataVal);
            }
        } else {
            opType = XChainLib.OpType.Conventional;
            cdHash = keccak256(userOp.callData);
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
     * @notice Executes a single call.
     * @param value The Ether value to send with the call.
     * @param dest The destination address for the call.
     * @param func The function data (call data) to execute.
     */
    function xCall(uint256 value, address dest, bytes calldata func) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }
}
