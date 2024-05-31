// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE} from "I4337/artifacts/EntryPoint_0_6.sol";
import {ECDSAValidator,ValidationData} from "../lib/kernel/src/validator/ECDSAValidator.sol";
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
import {ECDSA} from "../src/ECDSA.sol";
import "forge-std/Test.sol";

contract KernelPluginModeTest is Test {
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    IEntryPoint entryPoint;
    ECDSAValidator _defaultValidator;

    KernelIntentValidator intentValidator;
    KernelIntentExecutor intentExecutor;

    address private _ownerAddress;
    uint256 private _ownerPrivateKey;
    address private _factoryOwnerAddress;
    string _network;
    IKernel _account;
    KernelFactory _factory;
    Kernel kernelImpl;
    address private targetContractAddress;

    function setUp() public {
        entryPoint = IEntryPoint(payable(ENTRYPOINT_V06));
        vm.etch(ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE);
        readEnvVars();

        // Create default ECDSA account
        vm.startPrank(_factoryOwnerAddress);
        kernelImpl = new Kernel(entryPoint);
        _factory = new KernelFactory(_factoryOwnerAddress, entryPoint);
        _factory.setImplementation(address(kernelImpl), true);
        _defaultValidator = new ECDSAValidator();

        // Plugin setup and intent execution
        intentExecutor = new KernelIntentExecutor();
        intentValidator = new KernelIntentValidator();

        // Deploy a test target contract (could be any contract with functions to call)
        vm.startPrank(_ownerAddress);
        FooContract targetContract = new FooContract();
        targetContractAddress = address(targetContract);

        this.logSender();
    }

    function readEnvVars() public {
        string memory privateKeyString = vm.envString("ETHEREUM_PRIVATE_KEY");
        console2.log("privateKeyString:", privateKeyString);

        string memory factoryOwnerPrvKeyString = vm.envString("ETHEREUM_KERNEL_FACTORY_OWNER_PRIVATE_KEY");
        _factoryOwnerAddress = vm.addr(vm.parseUint(factoryOwnerPrvKeyString));

        // Derive the Ethereum address from the private key
        _ownerPrivateKey = vm.parseUint(privateKeyString);
        _ownerAddress = vm.addr(_ownerPrivateKey);

        console2.log("Owner address:", _ownerAddress);

        assertFalse(_ownerAddress == address(0), "Owner address should not be the zero address");
    }

    function getInitializeData() internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            KernelStorage.initialize.selector, _defaultValidator, abi.encodePacked(_ownerAddress)
        );
    }

    function _createAccount() internal {
        bytes memory initData = getInitializeData();
        _account = Kernel(payable(address(_factory.createAccount(address(kernelImpl), initData, 0))));
        vm.deal(address(_account), 1e30);
    }

    function registerExecutors(address ownerAddress, address executorAddress) internal {
        this.logSender();

        // Encode enableData with the owner address
        bytes memory enableData = abi.encodePacked(ownerAddress);

        // necessary: accepting from self or entry point
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

    function testRegistrationByApi() public {
        _createAccount();

        IKernelValidator validator = _account.getExecution(KernelIntentExecutor.doNothing.selector).validator;
        assertEq(address(validator), 0x0000000000000000000000000000000000000000, "Only default Validator is set");

        registerExecutors(_ownerAddress, address(intentExecutor));

        IKernelValidator validatorNew = _account.getExecution(KernelIntentExecutor.doNothing.selector).validator;
        assertNotEq(address(validator), address(validatorNew), "Validator should have changed");
        assertEq(address(validatorNew), address(intentValidator), "Validator should be intentValidator");
        assertEq(
            address(_account.getExecution(KernelIntentExecutor.doNothing.selector).executor),
            address(intentExecutor),
            "Executor should be intentExecutor"
        );

        vm.startPrank(_ownerAddress);

        logSender();

        // Test doNothing() in new validator
        (bool success,) = address(_account).call(abi.encodeWithSelector(KernelIntentExecutor.doNothing.selector));
        assertTrue(success, "doNothing failed");

        // Test execute()
        bytes memory data = abi.encodeWithSignature("doSomething()");

        // Expect the DidSomething event to be emitted
        /*
         * true: event to be emitted.
         * false: check the indexed parameters.
         * false: check non-indexed parameters of the event.
         * true: check the event's topic (function signature).
         */
        vm.expectEmit(true, true, true, true);
        emit FooContract.DidSomething(0);

        (success,) = address(_account).call(
            abi.encodeWithSelector(KernelIntentExecutor.execute.selector, targetContractAddress, 0, data)
        );
        assertTrue(success, "execute failed");

        // Test executeBatch
        address[] memory targets = new address[](2);
        targets[0] = targetContractAddress;
        targets[1] = targetContractAddress;
        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeWithSignature("doSomething()");
        datas[1] = abi.encodeWithSignature("doSomethingElse()");

        // Expect the DidSomething and DidSomethingElse events to be emitted
        emit FooContract.DidSomething(0);
        emit FooContract.DidSomethingElse(0);

        (success,) =
            address(_account).call(abi.encodeWithSelector(KernelIntentExecutor.executeBatch.selector, targets, datas));
        assertTrue(success, "executeBatch failed");

        // Test execValueBatch
        uint256[] memory values = new uint256[](2);
        values[0] = 1 ether;
        values[1] = 2 ether;
        targets = new address[](2);
        targets[0] = targetContractAddress;
        targets[1] = targetContractAddress;
        datas = new bytes[](2);
        datas[0] = abi.encodeWithSignature("doSomething()");
        datas[1] = abi.encodeWithSignature("doSomethingElse()");

        // Expect the DidSomething and DidSomethingElse events to be emitted
        emit FooContract.DidSomething(values[0]);
        emit FooContract.DidSomethingElse(values[1]);

        (success,) = address(_account).call(
            abi.encodeWithSelector(KernelIntentExecutor.execValueBatch.selector, values, targets, datas)
        );
        assertTrue(success, "execValueBatch failed");
    }

    function testValidateSigVanillaOp() public {
        _createAccount();

        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: address(_account),
            nonce: 0x0,
            initCode: bytes(hex""),
            callData: bytes(hex""),
            callGasLimit: 500000,
            verificationGasLimit: 65536,
            preVerificationGas: 65536,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = _account.getNonce();
        console2.log("nonce:", userOp.nonce);

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid, _ownerPrivateKey);
        console2.log("signature:"); // 65 bytes or 130 hex characters. ECDSA signature
        console2.logBytes(userOp.signature);

        intentValidator.enable(abi.encodePacked(_ownerAddress));

        verifySignature(userOp);

        ValidationData v =
            _defaultValidator.validateUserOp(userOp, intentValidator.getUserOpHash(userOp, block.chainid), 0);
        assertEq(ValidationData.unwrap(v), 0, "Signature is not valid for the userOp");
    }

    function generateSignature(UserOperation memory userOp, uint256 chainID, uint256 signerPrvKey) view internal returns (bytes memory) {
        bytes32 userOpHash = intentValidator.getUserOpHash(userOp, chainID);

        // Sign the hash with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrvKey, ECDSA.toEthSignedMessageHash(userOpHash));

        // Combine (v, r, s) into a signature
        bytes memory signature = abi.encodePacked(r, s, v);

        return signature;
    }

    function verifySignature(UserOperation memory userOp) internal returns (uint256) {
        // not supplying the userOpHash as _validateSignature calls for the Intent version
        bytes32 userOpHash = intentValidator.getUserOpHash(userOp, block.chainid);
        ValidationData result = intentValidator.validateSignature(userOpHash, userOp.signature);
        assertEq(ValidationData.unwrap(result), 0, "Signature is not valid for the userOp");

        return ValidationData.unwrap(result);
    }

    // function testRegistrationByUserOp() public {
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

    // Pasted for reference
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
contract FooContract {
    event DidSomething(uint256 value);
    event DidSomethingElse(uint256 value);

    function doSomething() external payable {
        emit DidSomething(msg.value);
    }

    function doSomethingElse() external payable {
        emit DidSomethingElse(msg.value);
    }
}
