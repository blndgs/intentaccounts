// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import "../src/IntentUserOperation.sol";
import "./TestBytesHelper.sol";

library TestSimpleAccountHelper {
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 private constant SIGNATURE_LENGTH = 65;
    using TestBytesHelper for bytes;

    function getIntentHash(UserOperation memory userOp) internal pure returns (bytes32) {
        uint256 sigLength = userOp.signature.length;
        if (sigLength > SIGNATURE_LENGTH) {
            bytes memory intent = userOp.signature._slice(SIGNATURE_LENGTH,userOp.signature.length);
            return intent.memoryKeccak();
        }
        return userOp.callData.memoryKeccak();
    }

    function getSender(UserOperation memory userOp) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {
            data := calldataload(userOp)
        }
        return address(uint160(data));
    }

    function packIntentOp(UserOperation memory userOp, bytes32 hashedCD)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            getSender(userOp),
            userOp.nonce,
            userOp.initCode.memoryKeccak(),
            hashedCD,
            userOp.callGasLimit,
            userOp.verificationGasLimit,
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas,
            userOp.paymasterAndData.memoryKeccak()
        );
    }

    function hashIntentOp(UserOperation memory userOp, bytes32 hashedCD) internal pure returns (bytes32) {
        return keccak256(packIntentOp(userOp, hashedCD));
    }

    function _getUserOpHash(UserOperation memory userOp, uint256 chainID) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            hashIntentOp(userOp, getIntentHash(userOp)),
            ENTRYPOINT_V06,
            chainID
        ));
    }
}
