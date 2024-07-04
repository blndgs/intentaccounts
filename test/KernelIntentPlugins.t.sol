// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE} from "I4337/artifacts/EntryPoint_0_6.sol";
import {ECDSAValidator, ValidationData} from "../lib/kernel/src/validator/ECDSAValidator.sol";
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
import {
    KERNEL_STORAGE_SLOT,
    KERNEL_NAME,
    KERNEL_VERSION,
    VALIDATOR_APPROVED_STRUCT_HASH
} from "../lib/kernel/src/common/Constants.sol";
import {ValidAfter, ValidUntil} from "../lib/kernel/src/common/Types.sol";
import {WalletKernelStorage, ExecutionDetail} from "../lib/kernel/src/common/Structs.sol";
import {ECDSA} from "../src/ECDSA.sol";
import {EIP712Library} from "./EIP712Library.sol";
import "forge-std/Test.sol";

contract KernelIntentPluginsTest is Test {
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
        _defaultValidator = new ECDSAValidator();
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

    function initDefaultValidator() internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            KernelStorage.initialize.selector, _defaultValidator, abi.encodePacked(_ownerAddress)
        );
    }

    function _createAccount() internal {
        bytes memory initData = initDefaultValidator();
        _account = Kernel(payable(address(_factory.createAccount(address(kernelImpl), initData, 0))));
        vm.deal(address(_account), 1e30);
        intentValidator.enable(abi.encodePacked(_ownerAddress));
    }

    function initIntentValidator() internal view returns (bytes memory) {
        return
            abi.encodeWithSelector(KernelStorage.initialize.selector, intentValidator, abi.encodePacked(_ownerAddress));
    }

    function _createAccountIntent() internal {
        bytes memory initData = initIntentValidator();
        _account = Kernel(payable(address(_factory.createAccount(address(kernelImpl), initData, 0))));
        vm.deal(address(_account), 1e30);
        intentValidator.enable(abi.encodePacked(_ownerAddress));
    }

    function _createAccountIntent(uint256 key) internal returns (IKernel) {
        bytes memory initData = initIntentValidator();
        IKernel account = Kernel(payable(address(_factory.createAccount(address(kernelImpl), initData, key))));
        vm.deal(address(account), 1e30);
        intentValidator.enable(abi.encodePacked(_ownerAddress));
        return account;
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

    function testValidateEmptyOp() public {
        _createAccount();

        UserOperation memory userOp = createUserOp(address(_account), bytes(hex""));

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid, _ownerPrivateKey);
        console2.log("signature:"); // 65 bytes or 130 hex characters. ECDSA signature
        console2.logBytes(userOp.signature);

        verifySignature(userOp);

        ValidationData v =
            _defaultValidator.validateUserOp(userOp, intentValidator.getUserOpHash(userOp, block.chainid), 0);
        assertEq(ValidationData.unwrap(v), 0, "Signature is not valid for the userOp");
    }

    function testValidateEmptyIntentOp() public {
        _createAccountIntent();

        UserOperation memory userOp = createUserOp(address(_account), bytes(hex""));

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid, _ownerPrivateKey);
        console2.log("signature:"); // 65 bytes or 130 hex characters. ECDSA signature
        console2.logBytes(userOp.signature);

        verifySignature(userOp);

        ValidationData v =
            intentValidator.validateUserOp(userOp, intentValidator.getUserOpHash(userOp, block.chainid), 0);
        assertEq(ValidationData.unwrap(v), 0, "Signature is not valid for the userOp");
    }

    function testValidateIntentValidatorOp() public {
        _createAccountIntent();

        UserOperation memory userOp = createUserOp(
            address(_account),
            bytes(
                "{\"sender\":\"0xff6F893437e88040ffb70Ce6Aeff4CcbF8dc19A4\",\"from\":{\"type\":\"TOKEN\",\"address\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"amount\":\"0.8\",\"chainId\":\"1\"},\"to\":{\"type\":\"TOKEN\",\"address\":\"0xdac17f958d2ee523a2206206994597c13d831ec7\",\"chainId\":\"1\"}}"
            )
        );

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid, _ownerPrivateKey);
        console2.log("signature:"); // 65 bytes or 130 hex characters. ECDSA signature
        console2.logBytes(userOp.signature);

        verifySignature(userOp);

        ValidationData v =
            intentValidator.validateUserOp(userOp, intentValidator.getUserOpHash(userOp, block.chainid), 0);
        assertEq(ValidationData.unwrap(v), 0, "Signature is not valid for the userOp");
    }

    function testExecIntentOp() public {
        _createAccountIntent();

        UserOperation memory userOp = createUserOp(
            address(_account),
            bytes(
                "{\"sender\":\"0xff6F893437e88040ffb70Ce6Aeff4CcbF8dc19A4\",\"from\":{\"type\":\"TOKEN\",\"address\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"amount\":\"0.8\",\"chainId\":\"1\"},\"to\":{\"type\":\"TOKEN\",\"address\":\"0xdac17f958d2ee523a2206206994597c13d831ec7\",\"chainId\":\"1\"}}"
            )
        );

        uint256 prefix = VALIDATION_DEF_0;
        setKernelSignature(userOp, _ownerPrivateKey, prefix);

        solveUserOp(
            userOp,
            hex"18dfb3c7000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff00000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000128d9627aa4000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7869584cd00000000000000000000000010000000000000000000000000000000000000110000000000000000000000000000000015b9ca29df2cd4b929d481fcb4ab9642000000000000000000000000000000000000000000000000"
        );

        // simulate Kernel validation which removes the signature prefix
        userOp.signature = removeSigPrefix(userOp.signature);
        bytes32 nullBytes;
        intentValidator.validateUserOp(userOp, nullBytes, 0);

        // execute with the prefixed signature
        bytes memory prefixedSig = prefixSignature(userOp.signature, prefix);
        userOp.signature = prefixedSig;
        executeUserOp(userOp, payable(_ownerAddress));
    }

    function testExecIntentOpWith2ndAccountIntentValidator() public {
        // create account with the default validator
        _createAccount();
        IKernel newIntentAccount = _createAccountIntent(1);
        console2.log("newIntentAccount:", address(newIntentAccount));

        UserOperation memory userOp = createUserOp(
            address(newIntentAccount),
            bytes(
                string(
                    abi.encodePacked(
                        "{\"sender\":\"",
                        address(newIntentAccount),
                        "\",\"from\":{\"type\":\"TOKEN\",\"address\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"amount\":\"0.8\",\"chainId\":\"1\"},\"to\":{\"type\":\"TOKEN\",\"address\":\"0xdac17f958d2ee523a2206206994597c13d831ec7\",\"chainId\":\"1\"}}"
                    )
                )
            )
        );

        uint256 sigPrefix = VALIDATION_DEF_0;
        setKernelSignature(userOp, _ownerPrivateKey, sigPrefix);

        solveUserOp(
            userOp,
            hex"18dfb3c7000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff00000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000128d9627aa4000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7869584cd00000000000000000000000010000000000000000000000000000000000000110000000000000000000000000000000015b9ca29df2cd4b929d481fcb4ab9642000000000000000000000000000000000000000000000000"
        );

        // simulate Kernel validation which removes the signature prefix
        userOp.signature = removeSigPrefix(userOp.signature);
        bytes32 nullBytes;
        intentValidator.validateUserOp(userOp, nullBytes, 0);

        // execute with the prefixed signature
        bytes memory prefixedSig = prefixSignature(userOp.signature, sigPrefix);
        userOp.signature = prefixedSig;
        executeUserOp(userOp, payable(_ownerAddress));
    }

    function testExecIntentOpWithVanillaAccountChangeValidatorForExecBatch() public {
        // create account with the default validator
        _createAccount();

        // executeBatch is pointing to default validator and executor (no execution detail)
        ExecutionDetail memory detail = IKernel(address(_account)).getExecution(intentExecutor.executeBatch.selector);
        assertEq(detail.executor, address(0x0));
        assertEq(address(detail.validator), address(0x0));

        bytes4 selector = IKernel.setExecution.selector;

        UserOperation memory userOp = createUserOp(
            address(_account),
            abi.encodeWithSelector(
                selector,
                KernelIntentExecutor.executeBatch.selector,
                address(intentExecutor),
                address(intentValidator),
                ValidUntil.wrap(0),
                ValidAfter.wrap(0),
                getEnableData()
            )
        );

        userOp.signature = buildEnableSignature(
            userOp,
            selector, // selector must match the userOp calldata selector
            0,
            0,
            intentValidator,
            address(intentExecutor),
            _ownerPrivateKey
        );

        executeUserOp(userOp, payable(_ownerAddress));

        // // executeBatch is now pointing to Intent validator and executor
        detail = IKernel(address(_account)).getExecution(intentExecutor.executeBatch.selector);
        assertEq(detail.executor, address(intentExecutor));
        assertEq(address(detail.validator), address(intentValidator));

        // 2nd Intent userOp with the changed validator set to Intent
        userOp = createUserOp(
            address(_account),
            bytes(
                "{\"sender\":\"0xff6F893437e88040ffb70Ce6Aeff4CcbF8dc19A4\",\"from\":{\"type\":\"TOKEN\",\"address\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"amount\":\"0.8\",\"chainId\":\"1\"},\"to\":{\"type\":\"TOKEN\",\"address\":\"0xdac17f958d2ee523a2206206994597c13d831ec7\",\"chainId\":\"1\"}}"
            )
        );

        // Set signature to plugin mode to call execBatch
        uint256 sigPrefix = VALIDATION_PLUGIN_1;
        setKernelSignature(userOp, _ownerPrivateKey, VALIDATION_PLUGIN_1);

        solveUserOp(
            userOp,
            hex"18dfb3c7000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff00000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000128d9627aa4000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7869584cd00000000000000000000000010000000000000000000000000000000000000110000000000000000000000000000000015b9ca29df2cd4b929d481fcb4ab9642000000000000000000000000000000000000000000000000"
        );

        // simulate Kernel validation which removes the signature prefix
        userOp.signature = removeSigPrefix(userOp.signature);
        bytes32 nullBytes;
        intentValidator.validateUserOp(userOp, nullBytes, 0);

        // execute with the prefixed signature
        bytes memory prefixedSig = prefixSignature(userOp.signature, sigPrefix);
        userOp.signature = prefixedSig;

        executeUserOp(userOp, payable(_ownerAddress));
    }

    function testExecIntentOpWithVanillaAccountChangeDefaultValidator() public {
        // create account with the default validator
        _createAccount();

        // default validator is the Kernel account default validator
        address defaultValidator = address(IKernel(address(_account)).getDefaultValidator());
        assertEq(defaultValidator, address(defaultValidator));

        bytes4 selector = IKernel.setDefaultValidator.selector;

        UserOperation memory userOp =
            createUserOp(address(_account), getEnableSetDefaultCalldata(selector, address(intentValidator)));

        userOp.signature = buildEnableSignature(
            userOp,
            selector, /* selector must match the userOp calldata selector */
            0,
            0,
            intentValidator,
            address(intentExecutor),
            _ownerPrivateKey
        );

        executeUserOp(userOp, payable(_ownerAddress));

        // default validator changed to intentValidator
        defaultValidator = address(IKernel(address(_account)).getDefaultValidator());
        assertEq(defaultValidator, address(intentValidator));

        // 2nd Intent userOp with the changed validator set to Intent
        userOp = createUserOp(
            address(_account),
            bytes(
                "{\"sender\":\"0xff6F893437e88040ffb70Ce6Aeff4CcbF8dc19A4\",\"from\":{\"type\":\"TOKEN\",\"address\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"amount\":\"0.8\",\"chainId\":\"1\"},\"to\":{\"type\":\"TOKEN\",\"address\":\"0xdac17f958d2ee523a2206206994597c13d831ec7\",\"chainId\":\"1\"}}"
            )
        );

        uint256 sigPrefix = VALIDATION_DEF_0;
        setKernelSignature(userOp, _ownerPrivateKey, sigPrefix);

        solveUserOp(
            userOp,
            hex"18dfb3c7000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff00000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000128d9627aa4000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7869584cd00000000000000000000000010000000000000000000000000000000000000110000000000000000000000000000000015b9ca29df2cd4b929d481fcb4ab9642000000000000000000000000000000000000000000000000"
        );

        // simulate Kernel validation which removes the signature prefix
        userOp.signature = removeSigPrefix(userOp.signature);
        bytes32 nullBytes;
        intentValidator.validateUserOp(userOp, nullBytes, 0);

        // execute with the prefixed signature
        bytes memory prefixedSig = prefixSignature(userOp.signature, sigPrefix);
        userOp.signature = prefixedSig;
        executeUserOp(userOp, payable(_ownerAddress));
    }

    function testExecSetExecutionDoNothingOp() public {
        _createAccount();

        bytes memory enableData = abi.encodePacked(_ownerAddress);

        UserOperation memory userOp = createUserOp(
            address(_account),
            abi.encodeWithSelector(
                IKernel.setExecution.selector,
                KernelIntentExecutor.doNothing.selector,
                address(intentExecutor),
                address(intentValidator),
                ValidUntil.wrap(0),
                ValidAfter.wrap(0),
                enableData
            )
        );

        // Generate the signature without Kernel mode prefix
        userOp.signature = generateSignature(userOp, block.chainid, _ownerPrivateKey);

        ValidationData v =
            _defaultValidator.validateUserOp(userOp, intentValidator.getUserOpHash(userOp, block.chainid), 0);
        assertEq(ValidationData.unwrap(v), 0, "Signature is not valid for the userOp");

        // Signature creation with the validating mode
        userOp.signature = setKernelSignature(userOp, _ownerPrivateKey, VALIDATION_DEF_0);

        executeUserOp(userOp, payable(_ownerAddress));

        ExecutionDetail memory detail = IKernel(address(_account)).getExecution(intentExecutor.doNothing.selector);
        assertEq(detail.executor, address(intentExecutor));
        assertEq(address(detail.validator), address(intentValidator));
    }

    /**
     * This test demonstrates switching to Intent validator for an executor api (doNothing)
     * The disadvantage is that the first userOp with the enable signatures will be
     * validated by the default validator. The subsequent userOps will be validated
     * by the IntentValidator
     */
    function testSignatureModeEnableAndPluginMode() public {
        _createAccount();

        bytes4 selector = KernelIntentExecutor.doNothing.selector;

        UserOperation memory userOp = createUserOp(address(_account), getEnableDoNothingCalldata(selector));

        userOp.signature = buildEnableSignature(
            userOp,
            selector, /* selector must match the userOp calldata selector */
            0,
            0,
            intentValidator,
            address(intentExecutor),
            _ownerPrivateKey
        );

        executeUserOp(userOp, payable(_ownerAddress));

        ExecutionDetail memory detail = IKernel(address(_account)).getExecution(intentExecutor.doNothing.selector);
        assertEq(detail.executor, address(intentExecutor));
        assertEq(address(detail.validator), address(intentValidator));

        userOp = createUserOp(
            address(_account),
            abi.encodeWithSelector(
                KernelIntentExecutor.doNothing.selector, ValidUntil.wrap(0), ValidAfter.wrap(0), getEnableData()
            )
        );

        // execute doNothing() in plugin mode with the IntentValidator
        userOp.nonce = IKernel(_account).getNonce();
        userOp.signature = setKernelSignature(userOp, _ownerPrivateKey, VALIDATION_PLUGIN_1);
        executeUserOp(userOp, payable(_ownerAddress));
    }

    function testEnableIntentValidatorSetDefault() public {
        _createAccount();

        bytes4 selector = IKernel.setDefaultValidator.selector;

        UserOperation memory userOp =
            createUserOp(address(_account), getEnableSetDefaultCalldata(selector, address(intentValidator)));

        userOp.signature = buildEnableSignature(
            userOp,
            selector, /* selector must match the userOp calldata selector */
            0,
            0,
            intentValidator,
            address(intentExecutor),
            _ownerPrivateKey
        );

        executeUserOp(userOp, payable(_ownerAddress));

        // default validator changed to intentValidator
        address defaultValidator = address(IKernel(address(_account)).getDefaultValidator());
        assertEq(defaultValidator, address(intentValidator));

        // execute doNothing() with new validator
        userOp = createUserOp(address(_account), getEnableDoNothingCalldata(KernelIntentExecutor.doNothing.selector));
        userOp.signature = setKernelSignature(userOp, _ownerPrivateKey, VALIDATION_DEF_0);
        executeUserOp(userOp, payable(_ownerAddress));

        // default validator remains intentValidator
        defaultValidator = address(IKernel(address(_account)).getDefaultValidator());
        assertEq(defaultValidator, address(intentValidator));
    }

    function generateSignature(UserOperation memory userOp, uint256 chainID, uint256 signerPrvKey)
        internal
        view
        returns (bytes memory)
    {
        bytes32 userOpHash = intentValidator.getUserOpHash(userOp, chainID);
        console2.log("userOp hash generating sig:");
        console2.logBytes32(userOpHash);

        // Sign the hash with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrvKey, ECDSA.toEthSignedMessageHash(userOpHash));

        // Combine (v, r, s) into a signature
        bytes memory signature = abi.encodePacked(r, s, v);

        return signature;
    }

    // calldata for Kernel mode 2 (enable validator) with doNothing()
    function getEnableDoNothingCalldata(bytes4 selector) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(selector);
    }

    function getEnableSetDefaultCalldata(bytes4 selector, address arg) internal view returns (bytes memory) {
        return abi.encodeWithSelector(selector, arg, getEnableData());
    }

    function verifySignature(UserOperation memory userOp) public returns (uint256) {
        require(userOp.signature.length > 4, "Invalid signature length");

        bytes memory signature = userOp.signature;
        bytes4 prefix;
        prefix = bytes4(bytes.concat(signature[0], signature[1], signature[2], signature[3]));

        if (prefix == 0x00000000 || prefix == 0x00000001 || prefix == 0x00000002) {
            signature = _slice(signature, 4, signature.length);
        }

        UserOperation memory userOpCopy = cloneUserOperationForHash(userOp, userOp.callData, signature);

        bytes32 userOpHash = intentValidator.getUserOpHash(userOpCopy, block.chainid);
        console2.log("userOp hash verifying sig:");
        console2.logBytes32(userOpHash);

        ValidationData result = intentValidator.validateSignature(userOpHash, signature);
        assertEq(ValidationData.unwrap(result), 0, "Signature is not valid for the userOp");
        return ValidationData.unwrap(result);
    }

    function solveUserOp(UserOperation memory userOp, bytes memory solution) internal pure {
        // Append the original callData (Intent JSON) to the signature
        userOp.signature = bytes(abi.encodePacked(userOp.signature, userOp.callData));

        // Assign the provided solution to userOp.callData
        userOp.callData = solution;
    }

    function cloneUserOperationForHash(
        UserOperation memory original,
        bytes memory newCalldata,
        bytes memory newSignature
    ) internal pure returns (UserOperation memory) {
        return UserOperation(
            original.sender,
            original.nonce,
            original.initCode,
            newCalldata,
            original.callGasLimit,
            original.verificationGasLimit,
            original.preVerificationGas,
            original.maxFeePerGas,
            original.maxPriorityFeePerGas,
            original.paymasterAndData,
            newSignature
        );
    }

    function removeSigPrefix(bytes memory signature) internal pure returns (bytes memory) {
        require(signature.length > 4, "Invalid signature length");

        bytes4 prefix = bytes4(bytes.concat(signature[0], signature[1], signature[2], signature[3]));

        if (prefix == 0x00000000 || prefix == 0x00000001 || prefix == 0x00000002) {
            return _slice(signature, 4, signature.length);
        }

        return signature;
    }

    function prefixSignature(bytes memory signature, uint256 prefixValue) internal pure returns (bytes memory) {
        require(prefixValue <= 2, "Invalid prefix value");
        require(signature.length > 4, "Invalid signature length");

        bytes4 prefix = bytes4(bytes.concat(signature[0], signature[1], signature[2], signature[3]));

        if (prefix == 0x00000000 || prefix == 0x00000001 || prefix == 0x00000002) {
            return signature;
        }

        if (prefixValue == 0) {
            prefix = 0x00000000;
        } else if (prefixValue == 1) {
            prefix = 0x00000001;
        } else if (prefixValue == 2) {
            prefix = 0x00000002;
        }

        bytes memory prefixedSignature = new bytes(signature.length + 4);

        for (uint256 i = 0; i < 4; i++) {
            prefixedSignature[i] = prefix[i];
        }

        for (uint256 i = 0; i < signature.length; i++) {
            prefixedSignature[i + 4] = signature[i];
        }

        return prefixedSignature;
    }

    function buildEnableSignature(
        UserOperation memory op,
        bytes4 selector,
        uint48 validAfter,
        uint48 validUntil,
        IKernelValidator validator,
        address executor,
        uint256 signerPrvKey
    ) internal view returns (bytes memory sig) {
        require(address(validator) != address(0), "validator not set");
        require(executor != address(0), "executor not set");
        bytes memory enableData = getEnableData();
        bytes32 permitHash =
            EIP712Library.getStructHash(selector, validUntil, validAfter, address(validator), executor, enableData);
        bytes32 digest = EIP712Library.hashTypedData(KERNEL_NAME, KERNEL_VERSION, permitHash, op.sender);
        bytes memory enableSig = signHash(digest);
        sig = generateSignature(op, block.chainid, signerPrvKey);
        sig = abi.encodePacked(
            bytes4(0x00000002),
            validAfter,
            validUntil,
            address(validator),
            executor,
            uint256(enableData.length),
            enableData,
            enableSig.length,
            enableSig,
            sig
        );
    }

    // Custom errors
    error EndLessThanStart();
    error EndOutOfBounds(uint256 dataLength, uint256 end);
    error StartOutOfBounds(uint256 dataLength, uint256 start);

    /**
     * @dev Slices a bytes array to return a portion specified by the start and end indices.
     * @param data The bytes array to be sliced.
     * @param start The index in the bytes array where the slice begins.
     * @param end The index in the bytes array where the slice ends (exclusive).
     * @return result The sliced portion of the bytes array.
     * Note: The function reverts if the start index is not less than the end index,
     *       if start or end is out of the bounds of the data array.
     */
    function _slice(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory result) {
        if (end <= start) revert EndLessThanStart();
        if (end > data.length) revert EndOutOfBounds(data.length, end);
        if (start >= data.length) revert StartOutOfBounds(data.length, start);

        assembly {
            // Allocate memory for the result
            result := mload(0x40)
            mstore(result, sub(end, start)) // Set the length of the result
            let resultPtr := add(result, 0x20)

            // Copy the data from the start to the end
            for { let i := start } lt(i, end) { i := add(i, 0x20) } {
                let dataPtr := add(add(data, 0x20), i)
                mstore(add(resultPtr, sub(i, start)), mload(dataPtr))
            }

            // Update the free memory pointer
            mstore(0x40, add(resultPtr, sub(end, start)))
        }
    }

    function getEnableData() internal view returns (bytes memory) {
        return abi.encodePacked(_ownerAddress);
    }

    function signHash(bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_ownerPrivateKey, ECDSA.toEthSignedMessageHash(hash));
        return abi.encodePacked(r, s, v);
    }

    function createUserOp(address sender, bytes memory callData) internal view returns (UserOperation memory) {
        UserOperation memory userOp = UserOperation({
            sender: sender,
            nonce: 0,
            initCode: bytes(hex""),
            callData: callData,
            callGasLimit: 1000000,
            verificationGasLimit: 500000,
            preVerificationGas: 65536,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = IKernel(sender).getNonce();

        return userOp;
    }

    // default validation mode
    uint256 constant VALIDATION_DEF_0 = 0;
    // plugin validation mode
    uint256 constant VALIDATION_PLUGIN_1 = 1;
    // enable validator mode
    uint256 constant VALIATION_ENABLED_2 = 2;

    function setKernelSignature(UserOperation memory userOp, uint256 ownerPrivateKey, uint256 mode)
        internal
        returns (bytes memory)
    {
        userOp.signature = generateSignature(userOp, block.chainid, ownerPrivateKey);
        // verify sig without prefix
        verifySignature(userOp);

        bytes4 prefix;
        if (mode == VALIDATION_DEF_0) {
            prefix = bytes4(0x00000000);
        } else if (mode == VALIDATION_PLUGIN_1) {
            prefix = bytes4(0x00000001);
        } else if (mode == VALIATION_ENABLED_2) {
            prefix = bytes4(0x00000002);
        } else {
            revert("Invalid mode");
        }

        userOp.signature = abi.encodePacked(prefix, userOp.signature);
        // verify sig with prefix
        verifySignature(userOp);

        return userOp.signature;
    }

    function executeUserOp(UserOperation memory userOp, address payable beneficiary) public {
        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        IEntryPoint(entryPoint).handleOps(userOps, beneficiary);
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
