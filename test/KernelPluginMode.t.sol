// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSAValidator} from "../lib/kernel/src/validator/ECDSAValidator.sol";
import {IEntryPoint} from "../lib/kernel/lib/I4337/src/interfaces/IEntryPoint.sol";
import {IKernelValidator} from "../lib/kernel/src/interfaces/IKernelValidator.sol";
import {UserOperation} from "../lib/kernel/lib/I4337/src/interfaces/UserOperation.sol";
import {IKernel} from "../lib/kernel/src/interfaces/IKernel.sol";
import {KernelIntentExecutor} from "../src/KernelIntentExecutor.sol";
import {KernelIntentValidator} from "../src/KernelIntentECDSAValidator.sol";
import {Operation} from "../lib/kernel/src/common/Enums.sol";
import {Kernel} from "../lib/kernel/src/Kernel.sol";
import {KernelFactory} from "../lib/kernel/src/factory/KernelFactory.sol";
import {KernelStorage} from "../lib/kernel/src/abstract/KernelStorage.sol";
import {KERNEL_STORAGE_SLOT} from "../lib/kernel/src/common/Constants.sol";
import {ValidAfter, ValidUntil} from "../lib/kernel/src/common/Types.sol";
import {WalletKernelStorage, ExecutionDetail} from "../lib/kernel/src/common/Structs.sol";
import "forge-std/Test.sol";

contract KernelPluginModeTest is Test {
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    IEntryPoint entryPoint;
    ECDSAValidator _defaultValidator;

    IKernelValidator intentValidator;
    KernelIntentExecutor intentExecutor;

    address private _ownerAddress;
    uint256 private _ownerPrivateKey;
    string _network;
    IKernel _account;
    KernelFactory _factory;
    Kernel kernelImpl;

    function setOwner() public {
        string memory privateKeyString = vm.envString("ETHEREUM_PRIVATE_KEY");
        console2.log("privateKeyString:", privateKeyString);

        // Derive the Ethereum address from the private key
        _ownerPrivateKey = vm.parseUint(privateKeyString);
        _ownerAddress = vm.addr(_ownerPrivateKey);

        console2.log("Owner address:", _ownerAddress);

        // Assert that the owner address is not the zero address
        assertFalse(_ownerAddress == address(0), "Owner address should not be the zero address");
    }

    function getInitializeData() internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            KernelStorage.initialize.selector, _defaultValidator, abi.encodePacked(_ownerAddress)
        );
    }

    function _createAccount() internal {
        bytes memory initData = getInitializeData();
        console2.log("initData:");
        console2.logBytes(initData);
        _factory.setImplementation(address(kernelImpl), true);
        _account = Kernel(payable(address(_factory.createAccount(address(kernelImpl), initData, 0))));
        // console2.log("account nonce:", n);
        vm.deal(address(_account), 1e30);
    }

    function setUp() public {
        setOwner();
        vm.startPrank(_ownerAddress);
        this.logSender();
        entryPoint = IEntryPoint(payable(ENTRYPOINT_V06));
        _factory = new KernelFactory(_ownerAddress, entryPoint);
        console2.log("factory:", address(_factory));
        _defaultValidator = new ECDSAValidator();
        kernelImpl = new Kernel(entryPoint);
        console2.log("kernelImpl:", address(kernelImpl));
        _createAccount();
        intentExecutor = new KernelIntentExecutor();
        intentValidator = new KernelIntentValidator();
        registerExecutors(_ownerAddress, address(intentExecutor));
        console2.log("After registerExecutors");
        this.logSender();
    }

    function registerExecutors(address ownerAddress, address executorAddress) internal {
        console2.log("registerExecutors ownerAddress:", ownerAddress);
        this.logSender();
        // Encode enableData with the owner address
        bytes memory enableData = abi.encodePacked(ownerAddress);
        _defaultValidator.enable(enableData);
        intentValidator.enable(enableData);

        vm.startPrank(address(_account));

        // Register each function
        _account.setExecution(
            KernelIntentExecutor.doNothing.selector,
            executorAddress,
            intentValidator,
            ValidUntil.wrap(0),
            ValidAfter.wrap(0),
            enableData
        );

        _account.setExecution(
            KernelIntentExecutor.execute.selector,
            executorAddress,
            intentValidator,
            ValidUntil.wrap(0),
            ValidAfter.wrap(0),
            enableData
        );

        _account.setExecution(
            KernelIntentExecutor.executeBatch.selector,
            executorAddress,
            intentValidator,
            ValidUntil.wrap(0),
            ValidAfter.wrap(0),
            enableData
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
        vm.startPrank(_ownerAddress);
        logSender();
        // Test doNothing
        (bool success,) = address(_account).call(abi.encodeWithSelector(KernelIntentExecutor.doNothing.selector));
        assertTrue(success, "doNothing failed");

        // Test execute
        address target = address(0xdeadbeef);
        bytes memory data = abi.encodeWithSignature("doSomething()");
        (success,) =
            address(_account).call(abi.encodeWithSelector(KernelIntentExecutor.execute.selector, target, 0, data));
        assertTrue(success, "execute failed");

        // Test executeBatch
        address[] memory targets = new address[](2);
        targets[0] = address(0xdeadbeef);
        targets[1] = address(0xdeadbeef);
        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSignature("doSomething()");
        datas[1] = abi.encodeWithSignature("doSomethingElse()");
        (success,) =
            address(_account).call(abi.encodeWithSelector(KernelIntentExecutor.executeBatch.selector, targets, datas));
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
        (success,) = address(_account).call(
            abi.encodeWithSelector(KernelIntentExecutor.execValueBatch.selector, values, targets, datas)
        );
        assertTrue(success, "execValueBatch failed");
    }

    function logSender() public view {
        console2.log("msg.sender:", msg.sender);
    }

    function logExecutionDetails(bytes4 selector) public view {
        ExecutionDetail memory detail = _account.getExecution(selector);
        console2.log("detail.executor:", detail.executor);
        console2.log("detail.validator:", address(detail.validator));
        ValidUntil validUntil = detail.validUntil;
        ValidAfter validAfter = detail.validAfter;
        uint256 til;
        uint256 aft;
        assembly {
            til := sload(validUntil)
            aft := sload(validAfter)
        }
        console2.log(til);
        console2.log(aft);
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


     * Copied below from KernelStorage.sol for reference
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

// Example target contract for testing purposes
contract TestTarget {
    event DidSomething();
    event DidSomethingElse();

    function doSomething() external {
        emit DidSomething();
    }

    function doSomethingElse() external {
        emit DidSomethingElse();
    }
}
