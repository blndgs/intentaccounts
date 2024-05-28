// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {KernelTestBase} from "../lib/kernel/src/utils/KernelTestBase.sol";
import {IKernelValidator} from "../lib/kernel/src/interfaces/IKernelValidator.sol";
import {KernelIntentExecutor} from "../src/KernelIntentExecutor.sol";
import {UserOperation} from "../lib/kernel/lib/I4337/src/interfaces/UserOperation.sol";
import {ExecutionDetail} from "../lib/kernel/src/common/structs.sol";
import {IKernel} from "../lib/kernel/src/interfaces/IKernel.sol";
import "forge-std/Test.sol";

contract KernelPluginModeTest is Test {
    IKernelValidator intentValidator;
    KernelIntentExecutor executor;

    function setUp() public override {
        _initialize();
        intentValidator = IKernelValidator(0x0b250d3df2f90249cd70c746c6eac55c24c7c923);
        executor = new KernelIntentExecutor();
        _setAddress();
    }

    function test_set_execution_detail() public {
        bytes memory enableData = abi.encodePacked(owner);
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.setExecution.selector,
                executor.execute.selector,
                address(executor),
                intentValidator,
                uint48(0),
                uint48(0),
                enableData
            )
        );
        performUserOperationWithSig(op);
        ExecutionDetail memory detail = IKernel(address(kernel)).getExecution(executor.execute.selector);
        assertEq(detail.executor, address(executor));
        assertEq(address(detail.validator), address(intentValidator));
    }
}