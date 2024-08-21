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
    using XChainUserOpLib for UserOperation;
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
        bytes32 callData = calldataKeccak(userOp.callData);

        uint256 sigLength = userOp.signature.length;

        if (sigLength > SIGNATURE_LENGTH) {
            // There is an intent JSON at the end of the signature,
            // include the remaining part of signature > 65 (ECDSA len) to hashing
            callData = calldataKeccak(userOp.signature[SIGNATURE_LENGTH:]);
        }

        return keccak256(abi.encode(userOp.hashIntentOp(callData), address(entryPoint()), chainID));
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

    // Expose for testing to convert CallData value storage from memory to calldata
    function extractXChainCallData(XChainUserOpLib.ChainState state, bytes calldata combinedCallData) external pure returns (bytes memory) {
        return XChainUserOpLib.extractXChainCallData(state, combinedCallData);
    }

    // Expose for testing to convert teh callData value storage from memory to calldata
    function isXChainCallData(bytes calldata callData) external pure returns (bool) {
        return XChainUserOpLib.isXChainCallData(callData);
    }

    /**
     * execute a sequence of EVM calldata with Ether transfers.
     */
    function execValueBatch(uint256[] calldata values, address[] calldata dest, bytes[] calldata func) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], values[i], func[i]);
        }
    }

    /**
     * execute a sequence of EVM calldata with Ether transfers.
     */
    function xChainValueBatch(XChainUserOpLib.ChainState[] calldata states, uint256[] calldata values, address[] calldata dest, bytes[] calldata funcs) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == funcs.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            if (states[i] == XChainUserOpLib.ChainState.SAME_CHAIN) {
                _call(dest[i], values[i], funcs[i]);
            } else {
                bytes memory func = XChainUserOpLib.extractXChainCallData(states[i], funcs[i]);
                _call(dest[i], values[i], func);
            }
        }
    }

    /**
     * execute a sequence of EVM calldata with Ether transfers.
     */
    function xChainCall(XChainUserOpLib.ChainState state, uint256 value, address dest, bytes calldata xCallData) external {
        bytes memory func = XChainUserOpLib.extractXChainCallData(state, xCallData);
        _call(dest, value, func);
    }
}
