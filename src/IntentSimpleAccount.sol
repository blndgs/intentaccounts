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
        (XChainLib.UserOpType opType, bytes32 callDataHash, bytes32 otherChainHash) = _getCallDataHash(userOp);

        bytes32 opHash = keccak256(abi.encode(userOp.hashIntentOp(callDataHash), address(entryPoint()), chainID));

        if (opType == XChainLib.UserOpType.Conventional) {
            return opHash;
        } else {
            // link cross-chain hashes
            opHash = opHash ^ otherChainHash;
            return opHash;
        }
    }

    function _getCallDataHash(UserOperation calldata userOp)
        internal
        pure
        returns (XChainLib.UserOpType opType, bytes32 cdHash, bytes32 otherChainHash)
    {
        uint256 sigLength = userOp.signature.length;

        if (sigLength > SIGNATURE_LENGTH) {
            // There is an intent JSON at the end of the signature,
            // Intent userOp
            bytes calldata callDataVal = userOp.signature[SIGNATURE_LENGTH:];
            opType = XChainLib.identifyUserOpType(callDataVal);
            if (opType == XChainLib.UserOpType.CrossChain) {
                // Cross-chain UserOp
                (, otherChainHash) = XChainLib.extractChainIdHash(callDataVal);
                return (opType, keccak256(XChainLib.extractCallData(callDataVal)), otherChainHash);
            } else {
                return (opType, keccak256(callDataVal), otherChainHash);
            }
        } else {
            // We don't support cross-chain userOps for conventional userOps
            return (XChainLib.UserOpType.Conventional, keccak256(userOp.callData), otherChainHash);
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
     * Executes a batch of calls with specified values.
     * @param values The values (Ether amounts) to send with each call.
     * @param dest The destination addresses for each call.
     * @param func The function data (call data) for each call.
     */
    function execValueBatch(uint256[] calldata values, address[] calldata dest, bytes[] calldata func) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], values[i], func[i]);
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
