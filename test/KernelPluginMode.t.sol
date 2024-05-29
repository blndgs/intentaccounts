// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "../lib/kernel/lib/I4337/src/interfaces/IEntryPoint.sol";
import {IKernelValidator} from "../lib/kernel/src/interfaces/IKernelValidator.sol";
import {UserOperation} from "../lib/kernel/lib/I4337/src/interfaces/UserOperation.sol";
import {IKernel} from "../lib/kernel/src/interfaces/IKernel.sol";
import {KernelIntentExecutor} from "../src/KernelIntentExecutor.sol";
import {Operation} from "../lib/kernel/src/common/Enums.sol";
import {Kernel} from "../lib/kernel/src/Kernel.sol";
import {KernelFactory} from "../lib/kernel/src/factory/KernelFactory.sol";
import {KernelStorage} from "../lib/kernel/src/abstract/KernelStorage.sol";
import {KERNEL_STORAGE_SLOT} from "../lib/kernel/src/common/Constants.sol";
import {ValidAfter, ValidUntil} from "../lib/kernel/src/common/Types.sol";
import {WalletKernelStorage} from "../lib/kernel/src/common/Structs.sol";
import "forge-std/Test.sol";

contract KernelPluginModeTest is Test {
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    IEntryPoint entryPoint;

    IKernelValidator intentValidator;
    KernelIntentExecutor intentExecutor;

    address private _ownerAddress;
    uint256 private _ownerPrivateKey;
    string _network;
    IKernel _account;
    KernelFactory _factory;
    Kernel kernelImpl;

    function testSetOwner() public {
        string memory privateKeyEnv = string(abi.encodePacked(_network, "ETHEREUM_PRIVATE_KEY"));
        console2.log("NETWORK:", _network);
        string memory privateKeyString = vm.envString(privateKeyEnv);

        // Derive the Ethereum address from the private key
        _ownerPrivateKey = vm.parseUint(privateKeyString);
        _ownerAddress = vm.addr(_ownerPrivateKey);

        console2.log("Owner address:", _ownerAddress);

        // Assert that the owner address is not the zero address
        assertFalse(_ownerAddress == address(0), "Owner address should not be the zero address");
    }

    function getInitializeData() internal view returns (bytes memory) {
        IKernelValidator defValidator = getKernelStorage().defaultValidator;
        return abi.encodeWithSelector(KernelStorage.initialize.selector, defValidator, abi.encodePacked(_ownerAddress));
    }

    // Function to get the wallet kernel storage
    function getKernelStorage() internal pure returns (WalletKernelStorage storage ws) {
        assembly {
            ws.slot := KERNEL_STORAGE_SLOT
        }
    }

    function _createAccount() internal {
        _account = Kernel(payable(address(_factory.createAccount(address(kernelImpl), getInitializeData(), 0))));
        vm.deal(address(_account), 1e30);
    }

    function setUp() public {
        entryPoint = IEntryPoint(payable(ENTRYPOINT_V06));
        testSetOwner();
        _factory = KernelFactory(0x5de4839a76cf55d0c90e2061ef4386d962E15ae3);
        kernelImpl = new Kernel(entryPoint);
        _createAccount();
        intentExecutor = new KernelIntentExecutor();
        intentValidator = IKernelValidator(0x0B250D3dF2f90249CD70C746C6eaC55c24C7C923);
        registerExecutors(_ownerAddress, address(intentExecutor));
    }

    function registerExecutors(address ownerAddress, address executorAddress) internal {
        // Encode enableData with the owner address
        bytes memory enableData = abi.encodePacked(ownerAddress);

        // Register each function
        _account.setExecution(
            KernelIntentExecutor.doNothing.selector, executorAddress, intentValidator, ValidUntil.wrap(0), ValidAfter.wrap(0), enableData
        );
        _account.setExecution(
            KernelIntentExecutor.execute.selector, executorAddress, intentValidator, ValidUntil.wrap(0), ValidAfter.wrap(0), enableData
        );
        _account.setExecution(
            KernelIntentExecutor.executeBatch.selector, executorAddress, intentValidator, ValidUntil.wrap(0), ValidAfter.wrap(0), enableData
        );
        _account.setExecution(
            KernelIntentExecutor.execValueBatch.selector,
                executorAddress,
            intentValidator,
            ValidUntil.wrap(0),
            ValidAfter.wrap(0),
            enableData
        );
    }

    function testRegistration() public {
        // Test doNothing
        (bool success,) = address(_account).call(abi.encodeWithSelector(KernelIntentExecutor.doNothing.selector));
        assertTrue(success, "doNothing failed");

        // Test execute
        address target = address(0xdeadbeef);
        bytes memory data = abi.encodeWithSignature("doSomething()");
        (success,) = address(_account).call(abi.encodeWithSelector(KernelIntentExecutor.execute.selector, target, 0, data));
        assertTrue(success, "execute failed");

        // Test executeBatch
        address[] memory targets = new address[](2);
        targets[0] = address(0xdeadbeef);
        targets[1] = address(0xdeadbeef);
        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSignature("doSomething()");
        datas[1] = abi.encodeWithSignature("doSomethingElse()");
        (success,) = address(_account).call(abi.encodeWithSelector(KernelIntentExecutor.executeBatch.selector, targets, datas));
        assertTrue(success, "executeBatch failed");

        // Test execValueBatch
        uint256[] memory values = new uint256[](2);
        values[0] = 1 ether;
        values[1] = 2 ether;
        targets = new address[](2);
        targets[0] = address(0xdeadbeef);
        targets[1] = address(0xdeadbeef);
        datas = new bytes[](2);
        datas[0] = abi.encodeWithSignature("doSomething()");
        datas[1] = abi.encodeWithSignature("doSomethingElse()");
        (success,) = address(_account).call(abi.encodeWithSelector(KernelIntentExecutor.execValueBatch.selector, values, targets, datas));
        assertTrue(success, "execValueBatch failed");
    }
    
    // function test_set_execution_detail() public {
    //     bytes memory enableData = abi.encodePacked(_ownerAddress);
    //     UserOperation memory op = buildUserOperation(
    //         abi.encodeWithSelector(
    //             _account.setExecution.selector, address(intentValidator), address(intentExecutor), Operation.Call
    //         )
    //     );
    //     performUserOperationWithSig(op);
    //     ExecutionDetail memory detail = IKernel(address(kernel)).getExecution(executor.execute.selector);
    //     assertEq(detail.executor, address(executor));
    //     assertEq(address(detail.validator), address(intentValidator));
    // }

    /*
     * Copied below from KernelStorage.sol for reference
     */

    /// @notice Changes the execution details for a specific function selector
    /// @dev This function can only be called from the EntryPoint contract, the contract owner, or itself
    /// @param _selector The selector of the function for which execution details are being set
    /// @param _executor The executor to be associated with the function selector
    /// @param _validator The validator contract that will be responsible for validating operations associated with this function selector
    /// @param _validUntil The timestamp until which the execution details are valid
    /// @param _validAfter The timestamp after which the execution details are valid
    // function setExecution(
    //     bytes4 _selector,
    //     address _executor,
    //     IKernelValidator _validator,
    //     ValidUntil _validUntil,
    //     ValidAfter _validAfter,
    //     bytes calldata _enableData
    // ) external payable override onlyFromEntryPointOrSelf {
    //     getKernelStorage().execution[_selector] = ExecutionDetail({
    //         executor: _executor,
    //         validator: _validator,
    //         validUntil: _validUntil,
    //         validAfter: _validAfter
    //     });
    //     _validator.enable(_enableData);
    //     emit ExecutionChanged(_selector, _executor, address(_validator));
    // }

    // function setDefaultValidator(IKernelValidator _defaultValidator, bytes calldata _data)
    //     external
    //     payable
    //     virtual
    //     onlyFromEntryPointOrSelf
    // {
    //     IKernelValidator oldValidator = getKernelStorage().defaultValidator;
    //     getKernelStorage().defaultValidator = _defaultValidator;
    //     emit DefaultValidatorChanged(address(oldValidator), address(_defaultValidator));
    //     _defaultValidator.enable(_data);
    // }
}
