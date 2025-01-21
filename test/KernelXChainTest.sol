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
import {ECDSA} from "solady/utils/ECDSA.sol"; // used by the plugin
import {EIP712Library} from "./EIP712Library.sol";
import {XChainLib} from "../src/xchainlib.sol";
import "forge-std/Test.sol";

contract KernelXChainTest is Test {
    using ECDSA for bytes32;

    // --------------------------------------------
    // Constants
    // --------------------------------------------

    // We'll only use Polygon's chainId
    uint256 constant SINGLE_CHAIN_ID = 137;

    // You can set these to any recipients you want on your single chain
    address constant RECIPIENT_SRC = 0xd7b21a844f3a41c91a73d3F87B83fA93bb6cb518;
    address constant RECIPIENT_DEST = 0xE381bAB2e0C5b678F2FBb8D4b0949e41a6487c8f;

    // We'll maintain the same numeric constants for "mode", but we only use plugin=1 in practice
    uint256 constant VALIDATION_DEF_0 = 0;
    uint256 constant VALIDATION_PLUGIN_1 = 1;
    uint256 constant VALIATION_ENABLED_2 = 2;

    // --------------------------------------------
    // State variables
    // --------------------------------------------
    IEntryPoint public entryPoint;
    ECDSAValidator public defaultValidator;
    KernelIntentValidator public intentValidator;
    KernelIntentExecutor public intentExecutor;

    address public factoryOwnerAddress;
    address public ownerAddress;
    uint256 public ownerPrivateKey;
    IKernel public account;
    KernelFactory public factory;
    Kernel public kernelImpl;
    uint256 public polyFork; // We only use this one fork

    // --------------------------------------------
    // Setup
    // --------------------------------------------

    /**
     * @dev We only have one fork = polygon. We do not create or select BSC or chainId=56.
     *      Then we set up our single kernel account + factory on polygon.
     */
    function setUp() public {
        readEnvVars();
        setKernelFork(polyFork);
    }

    function readEnvVars() public {
        // Derive the Ethereum address from the private key
        string memory privateKeyString = vm.envString("WALLET_OWNER_KEY");
        ownerPrivateKey = vm.parseUint(privateKeyString);
        ownerAddress = vm.addr(ownerPrivateKey);

        console2.log("Owner address:", ownerAddress);
        assertFalse(ownerAddress == address(0), "Owner address should not be the zero address");

        // Create the polygon fork
        string memory urlEnv = "POLYGON_RPC_URL";
        polyFork = vm.createFork(vm.envString(urlEnv));
    }

    /**
     * @dev Deploy a new Kernel and factory on a given fork. We only do it once (on polygon).
     */
    function setKernelFork(uint256 fork) internal {
        vm.selectFork(fork);

        // The official "EntryPoint v0.6" you used
        address entryPointV06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
        entryPoint = IEntryPoint(payable(entryPointV06));

        // 1) Initialize the factory and kernel
        // at v2.4 known deployed addresses
        factory = KernelFactory(0x5de4839a76cf55d0c90e2061ef4386d962E15ae3);
        kernelImpl = Kernel(payable (0xd3082872F8B06073A021b4602e022d5A070d7cfC));

        // 2) Default validator ECDSA
        // v2 0xd9AB5096a832b9ce79914329DAEE236f8Eea0390
        // v3 0x845ADb2C711129d4f3966735eD98a9F09fC4cE57
        defaultValidator = ECDSAValidator(0xd9AB5096a832b9ce79914329DAEE236f8Eea0390);

        // 3) Deploy our plugin (intent) validator + executor
        intentExecutor = new KernelIntentExecutor();
        intentValidator = new KernelIntentValidator();

        // Create account with non-intent validator by default
        vm.deal(ownerAddress, 1e30);
        vm.startPrank(ownerAddress);

        bytes memory initData =
            abi.encodeWithSelector(kernelImpl.initialize.selector, defaultValidator, abi.encodePacked(ownerAddress));
        account = Kernel(payable(address(factory.createAccount(address(kernelImpl), initData, 0))));

        // Fund the new kernel account
        vm.deal(address(account), 1e30);

        vm.stopPrank();
    }

    // --------------------------------------------
    // Example: Basic single-chain "Cross-Chain" test
    // --------------------------------------------

    /**
     * @dev
     * This test re-uses chainId=137 for both userOps. We still have "srcUserOp" and "destUserOp",
     * but we do *not* select a second fork or a second chain ID. This simulates cross-chain
     * signing in a single chain environment.
     *
     * - We do "enable" the kernel's plugin with an enableUserOp (nonce=0).
     * - We prepare 2 userOps (src & dest), each with chainId=137.
     * - We sign them with xSignCommon, do final "solver" adjustments, then
     *   call handleOps in sequence: userOp #1 (nonce=1) then userOp #2 (nonce=2).
     */
    function testKernelCrossChainValidationWithExecutionSingleChainSim() public {
        // Step 1: Enable the plugin-based execution on chain (nonce=0).
        UserOperation memory enableUserOp = buildEnableExecValueBatchOp();
        uint256 currentNonce = IKernel(address(account)).getNonce();
        enableUserOp.nonce = currentNonce;

        enableUserOp.signature = buildEnableSignature(
            enableUserOp, IKernel.setExecution.selector, 0, 0, intentValidator, address(intentExecutor), ownerPrivateKey
        );

        // We'll handleOps for this single userOp
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = enableUserOp;

        // We expect an event from the EntryPoint
        vm.expectEmit(false, true, true, false);
        emit IEntryPoint.UserOperationEvent(0, address(account), address(0), enableUserOp.nonce, true, 0, 0);

        // Actually execute: sets the plugin-based "execValueBatch" on the kernel
        entryPoint.handleOps(ops, payable(ownerAddress));

        // Step 2: Prepare 2 userOps with chainId=137
        (UserOperation memory srcUserOp, UserOperation memory destUserOp) = prepareCrossChainUserOps();

        // Step 3: Execute the "source" userOp
        // It has nonce = 1 (since we used up nonce=0 with the enableUserOp).
        executeXChainUserOp(srcUserOp.nonce, srcUserOp, destUserOp, true);

        // Step 4: Execute the "destination" userOp on the same chain
        executeXChainUserOp(destUserOp.nonce, srcUserOp, destUserOp, false);
    }

    /**
     * @dev
     * Have one chain ID = 137.
     * isSourceChain==true => it uses srcUserOp and does a transfer of 0.05 ether
     * isSourceChain==false => it uses destUserOp and does a transfer of 0.00005 ether
     */
    function executeXChainUserOp(
        uint256 currentNonce,
        UserOperation memory srcUserOp,
        UserOperation memory destUserOp,
        bool isSourceChain
    ) internal {
        if (isSourceChain) {
            srcUserOp.nonce = currentNonce;
            validateAndExecute(srcUserOp, SINGLE_CHAIN_ID, 0.05 ether, RECIPIENT_SRC);
        } else {
            destUserOp.nonce = currentNonce;
            validateAndExecute(destUserOp, SINGLE_CHAIN_ID, 0.00005 ether, RECIPIENT_DEST);
        }

        // Check the next nonce increments
        uint256 nextNonce = IKernel(address(account)).getNonce();
        assertEq(nextNonce, currentNonce + 1, "nonce should have incremented by 1");
    }

    /**
     * @dev
     * Creates 2 userOps with "intents", sets their nonces, and does cross-chain signing.
     * But we ONLY use chainId=137 for both.
     */
    function prepareCrossChainUserOps() internal view returns (UserOperation memory, UserOperation memory) {
        bytes memory srcIntent = createIntent();
        bytes memory destIntent = createIntent();

        UserOperation memory srcUserOp = createUserOp(address(account), srcIntent);
        UserOperation memory destUserOp = createUserOp(address(account), destIntent);

        // The current nonce after enabling is 1
        uint256 srcNonce = IKernel(address(account)).getNonce();
        srcUserOp.nonce = srcNonce;
        // we can set the destination userOp to 2
        destUserOp.nonce = srcNonce + 1;

        // Now compute hashes and sign them with chainId=137
        bytes32 srcHash = intentValidator.getUserOpHash(srcUserOp, SINGLE_CHAIN_ID);
        bytes32 destHash = intentValidator.getUserOpHash(destUserOp, SINGLE_CHAIN_ID);

        // Cross-chain sign
        xSignCommon(srcHash, destHash, ownerPrivateKey, srcUserOp, destUserOp);

        // "solver" step: append final solver callData to signatures
        srcUserOp.signature = abi.encodePacked(srcUserOp.signature, srcUserOp.callData);
        destUserOp.signature = abi.encodePacked(destUserOp.signature, destUserOp.callData);

        return (srcUserOp, destUserOp);
    }

    /**
     * @dev Verifies signature on chainId=137, then calls handleOps to do the actual transfer.
     * The callData is replaced with execValueBatch(...)
     */
    function validateAndExecute(UserOperation memory userOp, uint256 chainId, uint256 amount, address recipient)
        internal
    {
        // We only have a single chain, so just check block.chainid matches 137
        require(block.chainid == chainId, "Chain ID mismatch in singleChainSim test");

        // 1) Replace userOp.callData with execValueBatch
        userOp.callData = abi.encodeWithSelector(
            KernelIntentExecutor.execValueBatch.selector,
            _singleValueArray(amount),
            _singleAddressArray(recipient),
            _singleBytesArray(abi.encodeWithSignature("transfer(address,uint256)", recipient, amount))
        );

        // 2) Verify signature. Must be valid for chainId=137.
        ValidationData result = intentValidator.validateUserOp(userOp, bytes32(0), 0);
        require(ValidationData.unwrap(result) == 0, "Validation failed");

        // 3) Add the 4-byte prefix for plugin-based execution
        userOp.signature = prefixSignature(userOp.signature, VALIDATION_PLUGIN_1);

        // 4) Execute via handleOps
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;

        vm.expectEmit(false, true, true, false);
        emit IEntryPoint.UserOperationEvent(0, address(account), address(0), userOp.nonce, true, 0, 0);

        entryPoint.handleOps(ops, payable(ownerAddress));
    }

    // ============ The rest is basically the same as your original code ============

    function buildEnableExecValueBatchOp() internal view returns (UserOperation memory) {
        bytes memory callData = abi.encodeWithSelector(
            IKernel.setExecution.selector,
            KernelIntentExecutor.execValueBatch.selector,
            address(intentExecutor),
            address(intentValidator),
            ValidUntil.wrap(0),
            ValidAfter.wrap(0),
            abi.encodePacked(ownerAddress)
        );

        UserOperation memory userOp = createUserOp(address(account), callData);
        userOp.nonce = IKernel(address(account)).getNonce();
        return userOp;
    }

    function createUserOp(address sender, bytes memory callData) internal view returns (UserOperation memory) {
        return UserOperation({
            sender: sender,
            nonce: IKernel(sender).getNonce(),
            initCode: "",
            callData: callData,
            callGasLimit: 800000,
            verificationGasLimit: 500000,
            preVerificationGas: 50000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: "",
            signature: ""
        });
    }

    /**
     * @dev This is your standard "intent" data.
     */
    function createIntent() internal pure returns (bytes memory) {
        return bytes(
            '{"fromAsset":{"address":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",'
            '"amount":{"value":"I4byb8EAAA=="},"chainId":{"value":"iQ=="}},'
            '"toStake":{"address":"0x1adB950d8bB3dA4bE104211D5AB038628e477fE6",'
            '"amount":{"value":"D0JA"},"chainId":{"value":"OA=="}}}'
        );
    }

    /**
     * @dev The cross-chain signature aggregator.
     *      We only do chainId=137 for both userOps, but we still produce a single
     *      ECDSA over (srcHash || destHash).
     */
    function xSignCommon(
        bytes32 hash1,
        bytes32 hash2,
        uint256 privateKey,
        UserOperation memory sourceUserOp,
        UserOperation memory destUserOp
    ) internal pure {
        // Compare for ordering
        bool shouldReverse = uint256(hash1) > uint256(hash2);

        bytes32 xChainHash =
            shouldReverse ? keccak256(abi.encodePacked(hash2, hash1)) : keccak256(abi.encodePacked(hash1, hash2));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, xChainHash.toEthSignedMessageHash());
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory placeholder = abi.encodePacked(uint16(XChainLib.XC_MARKER));
        bytes[] memory srcHashList = new bytes[](2);
        bytes[] memory destHashList = new bytes[](2);

        if (shouldReverse) {
            srcHashList[0] = abi.encodePacked(hash2);
            srcHashList[1] = placeholder;

            destHashList[0] = placeholder;
            destHashList[1] = abi.encodePacked(hash1);
        } else {
            srcHashList[0] = placeholder;
            srcHashList[1] = abi.encodePacked(hash2);

            destHashList[0] = abi.encodePacked(hash1);
            destHashList[1] = placeholder;
        }

        // Attach cross-chain data
        sourceUserOp.callData = createCrossChainCallData(sourceUserOp.callData, srcHashList);
        destUserOp.callData = createCrossChainCallData(destUserOp.callData, destHashList);

        sourceUserOp.signature = signature;
        destUserOp.signature = signature;
    }

    function createCrossChainCallData(bytes memory intent, bytes[] memory hashList)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory result =
            abi.encodePacked(uint16(XChainLib.XC_MARKER), uint16(intent.length), intent, uint8(hashList.length));

        for (uint256 i = 0; i < hashList.length; i++) {
            result = abi.encodePacked(result, hashList[i]);
        }
        return result;
    }

    function _singleValueArray(uint256 val) internal pure returns (uint256[] memory arr) {
        arr = new uint256[](1);
        arr[0] = val;
    }

    function _singleAddressArray(address addr) internal pure returns (address[] memory arr) {
        arr = new address[](1);
        arr[0] = addr;
    }

    function _singleBytesArray(bytes memory data) internal pure returns (bytes[] memory arr) {
        arr = new bytes[](1);
        arr[0] = data;
    }

    function prefixSignature(bytes memory signature, uint256 prefixValue) internal pure returns (bytes memory) {
        require(prefixValue <= 2, "Invalid prefix value");
        require(signature.length > 4, "Invalid signature length");

        bytes4 existingPrefix = bytes4(bytes.concat(signature[0], signature[1], signature[2], signature[3]));
        bool hasPrefix = (existingPrefix == 0x00000000 || existingPrefix == 0x00000001 || existingPrefix == 0x00000002);

        bytes memory sigWithoutPrefix = hasPrefix ? slice(signature, 4, signature.length) : signature;

        bytes4 newPrefix;
        if (prefixValue == 0) newPrefix = 0x00000000;
        else if (prefixValue == 1) newPrefix = 0x00000001;
        else if (prefixValue == 2) newPrefix = 0x00000002;

        bytes memory prefixedSignature = new bytes(sigWithoutPrefix.length + 4);
        for (uint256 i = 0; i < 4; i++) {
            prefixedSignature[i] = newPrefix[i];
        }
        for (uint256 i = 0; i < sigWithoutPrefix.length; i++) {
            prefixedSignature[i + 4] = sigWithoutPrefix[i];
        }
        return prefixedSignature;
    }

    // Helper: slicing bytes
    error EndLessThanStart();
    error EndOutOfBounds(uint256 dataLength, uint256 end);
    error StartOutOfBounds(uint256 dataLength, uint256 start);

    function slice(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory result) {
        if (end <= start) revert EndLessThanStart();
        if (end > data.length) revert EndOutOfBounds(data.length, end);
        if (start >= data.length) revert StartOutOfBounds(data.length, start);

        assembly {
            result := mload(0x40)
            mstore(result, sub(end, start))
            let resultPtr := add(result, 0x20)
            for { let i := start } lt(i, end) { i := add(i, 0x20) } {
                let dataPtr := add(add(data, 0x20), i)
                mstore(add(resultPtr, sub(i, start)), mload(dataPtr))
            }
            mstore(0x40, add(resultPtr, sub(end, start)))
        }
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
        bytes memory enableData = abi.encodePacked(ownerAddress);

        bytes32 permitHash =
            EIP712Library.getStructHash(selector, validUntil, validAfter, address(validator), executor, enableData);

        bytes32 digest = EIP712Library.hashTypedData(KERNEL_NAME, KERNEL_VERSION, permitHash, op.sender);

        bytes memory enableSig = signHash(digest);
        sig = generateSignature(op, block.chainid, signerPrvKey);

        // prefix: 0x00000002 for "enable" plus the rest
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

    function signHash(bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, ECDSA.toEthSignedMessageHash(hash));
        return abi.encodePacked(r, s, v);
    }

    function generateSignature(UserOperation memory userOp, uint256 chainID, uint256 signerPrvKey)
        internal
        view
        returns (bytes memory)
    {
        bytes32 userOpHash = intentValidator.getUserOpHash(userOp, chainID);
        console2.log("userOp hash generating sig:");
        console2.logBytes32(userOpHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrvKey, ECDSA.toEthSignedMessageHash(userOpHash));
        return abi.encodePacked(r, s, v);
    }

    // ============== Events ==============
    event IKernelEvent(string message);
    event IKernelInfo(address account, bytes data);

    // Must match IEntryPoint
    event IEntryPointUserOpRevertReason(
        bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason
    );

    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );
}
