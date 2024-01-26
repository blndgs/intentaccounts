// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.5 <0.9.0;

// solhint-disable no-inline-assembly

/**
 * Utility functions helpful when making different kinds of contract calls in Solidity.
 */
library Exec {

    /**
     * @dev Executes a regular contract call in the called's function storage context.
     * @param to The address of the contract to call.
     * @param value The amount of Ether to send with the call.
     * @param data The calldata to send with the call.
     * @param txGas The amount of gas to allocate for the call.
     * @return success A boolean indicating whether the call was successful.
     * Inline assembly is used to optimize gas consumption and direct control over the EVM.
     */
    function call(
        address to,
        uint256 value,
        bytes memory data,
        uint256 txGas
    ) internal returns (bool success) {
        assembly {
            success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
        }
    }

    /**
     * @dev Executes a static (view only) contract call to a specified address.
     * @param to The address of the contract to call.
     * @param data The calldata to send with the call.
     * @param txGas The amount of gas to allocate for the call.
     * @return success A boolean indicating whether the call was successful.
     * This function ensures that no state modifications occur during the call.
     */
    function staticcall(
        address to,
        bytes memory data,
        uint256 txGas
    ) internal view returns (bool success) {
        assembly {
            success := staticcall(txGas, to, add(data, 0x20), mload(data), 0, 0)
        }
    }

    /**
     * @dev Executes a delegate call in the caller's function storage context.
     * @param to The address of the contract to delegate call to.
     * @param data The calldata to send with the delegate call.
     * @param txGas The amount of gas to allocate for the delegate call.
     * @return success A boolean indicating whether the call was successful.
     * Delegate calls execute the code of the target address in the context of the calling contract.
     */
    function delegateCall(
        address to,
        bytes memory data,
        uint256 txGas
    ) internal returns (bool success) {
        assembly {
            success := delegatecall(txGas, to, add(data, 0x20), mload(data), 0, 0)
        }
    }

    /**
     * @dev Retrieves the return data from the last call or delegate call.
     * @param maxLen The maximum length of the return data to read.
     * @return returnData The bytes of the return data.
     * This function is useful for handling return data of unknown or variable size.
     */
    function getReturnData(uint256 maxLen) internal pure returns (bytes memory returnData) {
        assembly {
            let len := returndatasize()
            if gt(len, maxLen) {
                len := maxLen
            }
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, add(len, 0x20)))
            mstore(ptr, len)
            returndatacopy(add(ptr, 0x20), 0, len)
            returnData := ptr
        }
    }

    /**
     * @dev revert with explicit byte array (probably reverted info from call)
     * @param returnData The byte array to use as the revert reason.
     * This function allows for reverting with specific data, often used for error handling.
     */
    function revertWithData(bytes memory returnData) internal pure {
        assembly {
            revert(add(returnData, 32), mload(returnData))
        }
    }

    /**
     * @dev Performs a call and reverts the transaction if the call is unsuccessful.
     * @param to The address to call.
     * @param data The calldata to send.
     * @param maxLen The maximum length of the revert data to handle.
     * This function is a convenience method that combines a call and conditional revert.
     */
    function callAndRevert(address to, bytes memory data, uint256 maxLen) internal {
        bool success = call(to,0,data,gasleft());
        if (!success) {
            revertWithData(getReturnData(maxLen));
        }
    }
}
