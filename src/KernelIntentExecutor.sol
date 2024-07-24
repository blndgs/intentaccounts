// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {WalletKernelStorage} from "../lib/kernel/src/common/Structs.sol";
import {IKernel} from "../lib/kernel/src/interfaces/IKernel.sol";

contract KernelIntentExecutor {
    address private constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    event ExecutorDoNothing();
    event LogOwner(address indexed sender, address indexed contractAddress);

    function doNothing() external {
        emit LogOwner(msg.sender, address(this));
        emit ExecutorDoNothing();
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
     * execute a sequence of EVM calldata with Ether transfers.
     */
    function execValueBatch(uint256[] calldata values, address[] calldata dest, bytes[] calldata func) external {
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], values[i], func[i]);
        }
    }
}
