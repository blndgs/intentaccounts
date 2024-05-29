// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "../lib/kernel/lib/I4337/src/interfaces/IEntryPoint.sol";
import {IKernelValidator} from "../lib/kernel/src/interfaces/IKernelValidator.sol";
import {UserOperation} from "../lib/kernel/lib/I4337/src/interfaces/UserOperation.sol";
import {IKernel} from "../lib/kernel/src/interfaces/IKernel.sol";
import {KernelIntentExecutor} from "../src/KernelIntentExecutor.sol";
import {Kernel} from "../lib/kernel/src/Kernel.sol";
import {KernelFactory} from "../lib/kernel/src/factory/KernelFactory.sol";
import {KernelStorage} from "../lib/kernel/src/abstract/KernelStorage.sol";
import {KERNEL_STORAGE_SLOT} from "../lib/kernel/src/common/Constants.sol";
import {WalletKernelStorage} from "../lib/kernel/src/common/Structs.sol";
import "forge-std/Test.sol";
import "../lib/kernel/lib/solady/src/utils/ECDSA.sol";

contract KernelEnableModeTest is Test {
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
        intentValidator = IKernelValidator(0x0B250D3dF2f90249CD70C746C6eaC55c24C7C923);
        intentExecutor = new KernelIntentExecutor();
    }

    function test_enable_custom_validator() public {
        bytes memory enableData = abi.encodePacked(_ownerAddress);
        UserOperation memory op = fillUserOp(
            entryPoint,
            _ownerAddress,
            abi.encodeWithSelector(IKernel.setDefaultValidator.selector, intentValidator, enableData)
        );

        performUserOperationWithSig(op);
        assertEq(address(IKernel(address(_account)).getDefaultValidator()), address(intentValidator));
    }

    function signUserOp(UserOperation memory op) internal view returns (bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), signUserOpHash(entryPoint, vm, _ownerPrivateKey, op));
    }

    function performUserOperationWithSig(UserOperation memory op) internal {
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        address payable beneficiary = payable(0xa4BFe126D3aD137F972695dDdb1780a29065e556);
        entryPoint.handleOps(ops, beneficiary);
    }

    function signUserOpHash(IEntryPoint _entryPoint, Vm _vm, uint256 _key, UserOperation memory _op)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 hash = _entryPoint.getUserOpHash(_op);
        (uint8 v, bytes32 r, bytes32 s) = _vm.sign(_key, ECDSA.toEthSignedMessageHash(hash));
        signature = abi.encodePacked(r, s, v);
    }

    function fillUserOp(IEntryPoint _entryPoint, address _sender, bytes memory callData)
        internal
        view
        returns (UserOperation memory op)
    {
        op.sender = _sender;
        op.nonce = _entryPoint.getNonce(_sender, 0);
        op.callData = callData;
        op.callGasLimit = 10000000;
        op.verificationGasLimit = 10000000;
        op.preVerificationGas = 50000;
        op.maxFeePerGas = 50000;
        op.maxPriorityFeePerGas = 1;
    }
}
