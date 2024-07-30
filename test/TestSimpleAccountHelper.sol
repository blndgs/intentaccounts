// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import "../src/IntentUserOperation.sol";
import "./TestBytesHelper.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IntentSimpleAccountFactory} from "../src/IntentSimpleAccountFactory.sol";
import {IntentSimpleAccount} from "../src/IntentSimpleAccount.sol";
import "forge-std/Test.sol";
import "forge-std/Vm.sol";

library TestSimpleAccountHelper {
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 private constant SIGNATURE_LENGTH = 65;

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

//    struct PackedUserOp {
//        address sender;
//        uint256 nonce;
//        uint256 callGasLimit;
//        uint256 verificationGasLimit;
//        uint256 preVerificationGas;
//        uint256 maxFeePerGas;
//        uint256 maxPriorityFeePerGas;
//        bytes callData;
//    }

    function packUserOp(UserOperation memory userOp) internal pure returns (IntentSimpleAccount.PackedUserOp memory) {
        return IntentSimpleAccount.PackedUserOp({
            sender: userOp.sender,
            nonce: userOp.nonce,
            callGasLimit: userOp.callGasLimit,
            verificationGasLimit: userOp.verificationGasLimit,
            preVerificationGas: userOp.preVerificationGas,
            maxFeePerGas: userOp.maxFeePerGas,
            maxPriorityFeePerGas: userOp.maxPriorityFeePerGas,
            callData: userOp.callData
        });
    }

    function combineUserOps(UserOperation memory sourceOp, UserOperation memory destOp)
    internal
    pure
    returns (UserOperation memory)
    {
        IntentSimpleAccount.PackedUserOp memory packedDestOp = packUserOp(destOp);
        bytes memory encodedPackedDestOp = abi.encode(packedDestOp);

        bytes memory combinedCallData = abi.encodePacked(
            uint256(sourceOp.callData.length), // Store the length of source callData
            sourceOp.callData,
            encodedPackedDestOp
        );

        return UserOperation({
            sender: sourceOp.sender,
            nonce: sourceOp.nonce,
            initCode: sourceOp.initCode,
            callData: combinedCallData,
            callGasLimit: sourceOp.callGasLimit,
            verificationGasLimit: sourceOp.verificationGasLimit,
            preVerificationGas: sourceOp.preVerificationGas,
            maxFeePerGas: sourceOp.maxFeePerGas,
            maxPriorityFeePerGas: sourceOp.maxPriorityFeePerGas,
            paymasterAndData: sourceOp.paymasterAndData,
            signature: sourceOp.signature
        });
    }

    function printUserOperation(UserOperation memory userOp) internal pure {
        console2.log("UserOperation:");
        console2.log("  Sender:", userOp.sender);
        console2.log("  Nonce:", userOp.nonce);
        console2.log("  InitCode length:", userOp.initCode.length);
        console2.log("  CallData length:", userOp.callData.length);
        console2.log("  CallGasLimit:", userOp.callGasLimit);
        console2.log("  VerificationGasLimit:", userOp.verificationGasLimit);
        console2.log("  PreVerificationGas:", userOp.preVerificationGas);
        console2.log("  MaxFeePerGas:", userOp.maxFeePerGas);
        console2.log("  MaxPriorityFeePerGas:", userOp.maxPriorityFeePerGas);
        console2.log("  PaymasterAndData length:", userOp.paymasterAndData.length);
        console2.log("  Signature length:", userOp.signature.length);

        // Print hexadecimal representation of initCode, callData, paymasterAndData, and signature
        console2.log("  InitCode (hex):");
        console2.logBytes(userOp.initCode);
        console2.log("  CallData (hex):");
        console2.logBytes(userOp.callData);
        console2.log("  PaymasterAndData (hex):");
        console2.logBytes(userOp.paymasterAndData);
        console2.log("  Signature (hex):");
        console2.logBytes(userOp.signature);
    }
}
