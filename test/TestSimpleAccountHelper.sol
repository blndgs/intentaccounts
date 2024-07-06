// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import "../src/IntentUserOperation.sol";
import "./TestBytesHelper.sol";
import {IntentSimpleAccountFactory} from "../src/IntentSimpleAccountFactory.sol";

library TestSimpleAccountHelper {
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 private constant SIGNATURE_LENGTH = 65;

    using TestBytesHelper for bytes;

    function getIntentHash(UserOperation memory userOp) internal pure returns (bytes32) {
        uint256 sigLength = userOp.signature.length;
        if (sigLength > SIGNATURE_LENGTH) {
            bytes memory intent = userOp.signature._slice(SIGNATURE_LENGTH, userOp.signature.length);
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

    function packIntentOp(UserOperation memory userOp, bytes32 hashedCD) internal pure returns (bytes memory) {
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
        return keccak256(abi.encode(hashIntentOp(userOp, getIntentHash(userOp)), ENTRYPOINT_V06, chainID));
    }

    /**
     * @notice Generates the initCode for creating a new account using a wallet factory
     * @dev This function is used to create the initCode field in a UserOperation for account creation
     * @param factory The address of the wallet factory contract
     * @param owner The address that will own the new account
     * @param salt A unique value to ensure different wallet addresses for the same owner
     * @return bytes The initCode to be used in a UserOperation
     *
     * @custom:example
     * Input:
     *   factory: 0x1234567890123456789012345678901234567890
     *   owner: 0xaabbccddeeaabbccddeeaabbccddeeaabbccddee
     *   salt: 0x0000000000000000000000000000000000000000000000000000000000000001
     *
     * Output:
     *   0x1234567890123456789012345678901234567890
     *   5fbfb9cf
     *   000000000000000000000000aabbccddeeaabbccddeeaabbccddeeaabbccddee
     *   0000000000000000000000000000000000000000000000000000000000000001
     *
     * Explanation:
     * - First 20 bytes: Factory address
     * - Next 4 bytes: Function selector for 'createAccount(address,uint256)'
     * - Next 32 bytes: Owner address (padded)
     * - Last 32 bytes: Salt value
     */
    function getInitCode(IntentSimpleAccountFactory factory, address owner, uint256 salt)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(address(factory), abi.encodeWithSelector(factory.createAccount.selector, owner, salt));
    }
}
