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
     * @dev Expose _getUserOpHash
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
            return calldataKeccak(userOp.signature[SIGNATURE_LENGTH:]);
        }

        if (opType == XChainLib.UserOpType.Conventional) {
            return calldataKeccak(userOp.callData);
        } else {
            // Cross-chain UserOp
            bytes calldata callData = XChainLib.extractCallData(userOp.callData);
            return calldataKeccak(callData);
        }
    }

    /**
     * expose _validateSignature.
     * @param userOp the UserOperation to validate.
     * @param hash the hash of the UserOperation.
     * @return 0 if the signature is valid, or an error code.
     */
    function validateSignature(UserOperation calldata userOp, bytes32 hash) external returns (uint256) {
        return _validateSignature(userOp, hash);
    }

    /// implement template method of BaseAccount
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
    }

    /**
     * execute a sequence of EVM calldata with Ether transfers.
     */
    function execValueBatch(uint256[] calldata values, address[] calldata dest, bytes[] calldata func) public {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            XChainLib.UserOpType opType = XChainLib.identifyUserOpType(func[i]);
            if (opType == XChainLib.UserOpType.Conventional) {
                _call(dest[i], values[i], func[i]);
            } else {
                bytes memory extractedCallData = XChainLib.extractCallData(func[i]);
                _call(dest[i], values[i], extractedCallData);
            }
        }
    }

    /**
     * execute a sequence of EVM calldata with Ether transfers.
     */
    function xChainCall(bytes calldata func, uint256 value, address dest) external {
        _requireFromEntryPointOrOwner();
        XChainLib.UserOpType opType = XChainLib.identifyUserOpType(func);
        if (opType == XChainLib.UserOpType.Conventional) {
            _call(dest, value, func);
        } else {
            bytes memory extractedCallData = XChainLib.extractCallData(func);
            _call(dest, value, extractedCallData);
        }
    }

}
