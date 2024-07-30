// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@account-abstraction/samples/SimpleAccount.sol";
import "./IntentUserOperation.sol";
import "@account-abstraction/interfaces/IEntryPoint.sol";
import "forge-std/Test.sol";

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

        return 0; // Ok
    }

    struct PackedUserOp {
        address sender;
        uint256 nonce;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes callData;
    }

    function extractDestUserOp(UserOperation calldata combinedOp) external pure returns (UserOperation memory) {
        console2.log("Entered extractDestUserOp");
        console2.log("combinedOp.callData length:", combinedOp.callData.length);

        (uint256 sourceCallDataLength, bytes memory packedDestOpData) = extractPackedData(combinedOp.callData);
        console2.log("sourceCallDataLength:", sourceCallDataLength);

        PackedUserOp memory packedDestOp = decodePackedUserOp(packedDestOpData);

        return unpackUserOp(packedDestOp);
    }

    function extractPackedData(bytes calldata callData) internal pure returns (uint256, bytes memory) {
        require(callData.length >= 32, "Invalid callData length");

        uint256 sourceCallDataLength = uint256(bytes32(callData[:32]));
        console2.log("sourceCallDataLength:", sourceCallDataLength);

        require(callData.length > 32 + sourceCallDataLength, "Invalid callData format");

        bytes memory packedDestOpData = callData[32 + sourceCallDataLength:];
        console2.log("packedDestOpData length:", packedDestOpData.length);

        require(packedDestOpData.length > 0, "No packed destination UserOp found");

        console2.log("packedDestOpData:");
        console2.logBytes(packedDestOpData);

        return (sourceCallDataLength, packedDestOpData);
    }

    function decodePackedUserOp(bytes memory packedDestOpData) internal pure returns (PackedUserOp memory) {
        console2.log("Attempting to decode PackedUserOp");

        PackedUserOp memory packedDestOp = abi.decode(packedDestOpData, (PackedUserOp));

        console2.log("Decoding successful");
        logPackedUserOp(packedDestOp);

        return packedDestOp;
    }

    function logPackedUserOp(PackedUserOp memory packedDestOp) internal pure {
        console2.log("Decoded packedDestOp:");
        console2.log("  sender:", packedDestOp.sender);
        console2.log("  nonce:", packedDestOp.nonce);
        console2.log("  callGasLimit:", packedDestOp.callGasLimit);
        console2.log("  verificationGasLimit:", packedDestOp.verificationGasLimit);
        console2.log("  preVerificationGas:", packedDestOp.preVerificationGas);
        console2.log("  maxFeePerGas:", packedDestOp.maxFeePerGas);
        console2.log("  maxPriorityFeePerGas:", packedDestOp.maxPriorityFeePerGas);
        console2.log("  callData length:", packedDestOp.callData.length);
    }

    function unpackUserOp(PackedUserOp memory packedOp) internal pure returns (UserOperation memory) {
        console2.log("Unpacking UserOperation");
        return UserOperation({
            sender: packedOp.sender,
            nonce: packedOp.nonce,
            initCode: new bytes(0),
            callData: packedOp.callData,
            callGasLimit: packedOp.callGasLimit,
            verificationGasLimit: packedOp.verificationGasLimit,
            preVerificationGas: packedOp.preVerificationGas,
            maxFeePerGas: packedOp.maxFeePerGas,
            maxPriorityFeePerGas: packedOp.maxPriorityFeePerGas,
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });
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
}
