// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

library ScriptUintHelper {
    function _weiToEther(uint256 weiAmount) internal pure returns (uint256) {
        return weiAmount / 1 ether;
    }

    function _weiToGwei(uint256 weiAmount) internal pure returns (uint256) {
        return weiAmount / 1 gwei;
    }
}
