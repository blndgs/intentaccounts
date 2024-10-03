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

    uint256 private constant SIGNATURE_LENGTH = 65;

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

    /// Computes the hash for a UserOperation, handling both cross-chain and conventional operations
    /// @param userOp The UserOperation to process
    /// @return opHash The computed operation hash
    function _getUserOpHash(UserOperation calldata userOp, uint256 chainId) internal view returns (bytes32 opHash) {
        // Extract xData from the signature if present
        bytes calldata xData = userOp.signature.length > SIGNATURE_LENGTH
            ? userOp.signature[SIGNATURE_LENGTH:]
            : userOp.signature[0:0];

        // Parse the xData
        XChainLib.xCallData memory parsedData = XChainLib.parseXElems(xData);

        // Compute callDataHash for conventional operations
        if (parsedData.opType == XChainLib.OpType.Conventional) {
            if (xData.length > 0) {
                // Use xData as the callDataHash
                parsedData.callDataHash = keccak256(xData);
            } else {
                // Vanilla eip4337 operation
                parsedData.callDataHash = keccak256(userOp.callData);
            }
        }

        // Compute the initial opHash
        opHash = keccak256(abi.encode(userOp.hashIntentOp(parsedData.callDataHash), address(entryPoint()), chainId));

        // For cross-chain operations, compute the combined hash
        if (parsedData.opType == XChainLib.OpType.CrossChain) {
            opHash = XChainLib.computeCrossChainHash(opHash, parsedData.hashList, parsedData.hashCount);
        }

        return opHash;
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
