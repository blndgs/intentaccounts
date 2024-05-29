// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {WalletKernelStorage} from "../lib/kernel/src/common/Structs.sol";
import {IKernel} from "../lib/kernel/src/interfaces/IKernel.sol";

contract KernelIntentExecutor {
    address private constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    event ExecutorDoNothing();

    function doNothing() external {
        // do nothing
        emit ExecutorDoNothing();
    }

    // Modifier to check if the function is called by the entry point, the contract itself or the owner
    modifier onlyFromEntryPointOrSelf() {
        if (msg.sender != ENTRYPOINT_V06 && msg.sender != address(this)) {
            revert IKernel.NotAuthorizedCaller();
        }
        _;
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external onlyFromEntryPointOrSelf{
        _call(dest, value, func);
    }

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func) external onlyFromEntryPointOrSelf {
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    /**
     * execute a sequence of EVM calldata with Ether transfers.
     */
    function execValueBatch(uint256[] calldata values, address[] calldata dest, bytes[] calldata func) external onlyFromEntryPointOrSelf {
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], values[i], func[i]);
        }
    }

}