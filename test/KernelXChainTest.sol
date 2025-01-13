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
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 constant SOURCE_CHAIN_ID = 137; // Polygon
    uint256 constant DEST_CHAIN_ID = 56; // BSC

    address constant RECIPIENT_SRC = 0xd7b21a844f3a41c91a73d3F87B83fA93bb6cb518;
    address constant RECIPIENT_DEST = 0xE381bAB2e0C5b678F2FBb8D4b0949e41a6487c8f;

    // Validation mode constants
    uint256 constant VALIDATION_DEF_0 = 0; // default validation mode
    uint256 constant VALIDATION_PLUGIN_1 = 1; // plugin validation mode
    uint256 constant VALIATION_ENABLED_2 = 2; // "enable" validator mode

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
    uint256 public polyFork;
    uint256 public bscFork;

    // --------------------------------------------
    // Setup
    // --------------------------------------------
    function setUp() public {
        readEnvVars();
        setKernelFork(polyFork);
    }

    function readEnvVars() public {
        string memory factoryOwnerPrvKeyString = vm.envString("ETHEREUM_KERNEL_FACTORY_OWNER_PRIVATE_KEY");
        factoryOwnerAddress = vm.addr(vm.parseUint(factoryOwnerPrvKeyString));

        // Derive the Ethereum address from the private key
        string memory privateKeyString = vm.envString("WALLET_OWNER_KEY");
        ownerPrivateKey = vm.parseUint(privateKeyString);
        ownerAddress = vm.addr(ownerPrivateKey);

        console2.log("Owner address:", ownerAddress);
        assertFalse(ownerAddress == address(0), "Owner address should not be the zero address");

        string memory urlEnv = "POLYGON_RPC_URL";
        polyFork = vm.createFork(vm.envString(urlEnv));

        urlEnv = "BSC_RPC_URL";
        bscFork = vm.createFork(vm.envString(urlEnv));
    }

    function setKernelFork(uint256 fork) internal {
        vm.selectFork(fork);
        entryPoint = IEntryPoint(payable(ENTRYPOINT_V06));

        // 1) Create a Kernel implementation
        vm.deal(factoryOwnerAddress, 1e30);
        vm.startPrank(factoryOwnerAddress);
        kernelImpl = new Kernel(entryPoint);
        factory = new KernelFactory(factoryOwnerAddress, entryPoint);
        factory.setImplementation(address(kernelImpl), true);

        // 2) Default validator is ECDSA
        defaultValidator = new ECDSAValidator();

        // 3) Deploy our plugin (intent) validator + executor
        intentExecutor = new KernelIntentExecutor();
        intentValidator = new KernelIntentValidator();

        // Create account with intent validator by default
        vm.deal(ownerAddress, 1e30);
        bytes memory initData =
            abi.encodeWithSelector(kernelImpl.initialize.selector, intentValidator, abi.encodePacked(ownerAddress));
        account = Kernel(payable(address(factory.createAccount(address(kernelImpl), initData, 0))));
        vm.deal(address(account), 1e30);
    }

    // --------------------------------------------
    // Example: Basic test with cross-chain signing
    // --------------------------------------------
    function testKernelCrossChainValidationBasic() public {
        // Create source/dest userOps with "intents"
        bytes memory srcIntent = createIntent();
        bytes memory destIntent = createIntent();

        UserOperation memory srcUserOp = createUserOp(address(account), srcIntent);
        UserOperation memory destUserOp = createUserOp(address(account), destIntent);

        // Compute chain-specific hashes
        bytes32 srcHash = intentValidator.getUserOpHash(srcUserOp, SOURCE_CHAIN_ID);
        bytes32 destHash = intentValidator.getUserOpHash(destUserOp, DEST_CHAIN_ID);

        // UI signs the source and destination userOps
        xSignCommon(srcHash, destHash, ownerPrivateKey, srcUserOp, destUserOp);

        // solve sourceUserOp which means the source userOp receives the EVM calldata solution
        // Solver step: append callData => userOp.signature
        // Bundler => solver => solve sourceUserOp
        srcUserOp.signature = abi.encodePacked(srcUserOp.signature, srcUserOp.callData);
        srcUserOp.callData = abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT_SRC, 0.05 ether);

        destUserOp.signature = abi.encodePacked(destUserOp.signature, destUserOp.callData);
        destUserOp.callData = abi.encodeWithSignature("transfer(address,uint256)", RECIPIENT_DEST, 0.00005 ether);

        // Validate them on each chain
        vm.chainId(SOURCE_CHAIN_ID);
        assertEq(SOURCE_CHAIN_ID, block.chainid, "Chain ID should match");

        ValidationData srcResult = intentValidator.validateUserOp(srcUserOp, bytes32(0), 0);
        assertEq(ValidationData.unwrap(srcResult), 0, "Source chain validation failed");

        vm.chainId(DEST_CHAIN_ID);
        ValidationData destResult = intentValidator.validateUserOp(destUserOp, bytes32(0), 0);
        assertEq(ValidationData.unwrap(destResult), 0, "Destination chain validation failed");
    }

    function executeXChainUserOp(
        uint256 currentNonce,
        UserOperation memory srcUserOp,
        UserOperation memory destUserOp,
        bool isSourceChain
    ) internal {
        // The cross-chain userOp uses the provided nonce
        if (isSourceChain) {
            srcUserOp.nonce = currentNonce;
            // Execute on the "source" chain
            validateAndExecute(srcUserOp, SOURCE_CHAIN_ID, 0.05 ether, RECIPIENT_SRC);
        } else {
            destUserOp.nonce = currentNonce;
            // Execute on the "destination" chain
            validateAndExecute(destUserOp, DEST_CHAIN_ID, 0.00005 ether, RECIPIENT_DEST);
        }

        // Get and verify next nonce
        uint256 nextNonce = IKernel(address(account)).getNonce();
        assertEq(nextNonce, currentNonce + 1, "nonce should have incremented by 1");
    }

    function testKernelCrossChainValidationWithExecution() public {
        // ---- POLYGON SETUP & EXECUTION ----

        // Build + execute enable userOp on Polygon
        UserOperation memory enableUserOpPoly = buildEnableExecValueBatchOp();
        uint256 currentNonce = IKernel(address(account)).getNonce();
        enableUserOpPoly.nonce = currentNonce;

        enableUserOpPoly.signature = buildEnableSignature(
            enableUserOpPoly,
            IKernel.setExecution.selector,
            0,
            0,
            intentValidator,
            address(intentExecutor),
            ownerPrivateKey
        );

        // Execute enable userOp on Polygon
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = enableUserOpPoly;

        vm.expectEmit(false, true, true, false);
        emit IEntryPoint.UserOperationEvent(0, address(account), address(0), enableUserOpPoly.nonce, true, 0, 0);
        entryPoint.handleOps(ops, payable(ownerAddress));

        // Create cross-chain userOps (this will handle nonces correctly)
        (UserOperation memory srcUserOp, UserOperation memory destUserOp) = prepareCrossChainUserOps();

        // Execute on Polygon (source chain)
        executeXChainUserOp(srcUserOp.nonce, srcUserOp, destUserOp, true);

        // ---- BSC SETUP & EXECUTION ----
        // Switch to BSC fork and set up environment
        setKernelFork(bscFork);

        // Build + execute enable userOp on BSC first
        UserOperation memory enableUserOpBSC = buildEnableExecValueBatchOp();
        currentNonce = IKernel(address(account)).getNonce();

        enableUserOpBSC.nonce = currentNonce;

        enableUserOpBSC.signature = buildEnableSignature(
            enableUserOpBSC,
            IKernel.setExecution.selector,
            0,
            0,
            intentValidator,
            address(intentExecutor),
            ownerPrivateKey
        );

        ops[0] = enableUserOpBSC;

        vm.expectEmit(false, true, true, false);
        emit IEntryPoint.UserOperationEvent(0, address(account), address(0), enableUserOpBSC.nonce, true, 0, 0);
        entryPoint.handleOps(ops, payable(ownerAddress));

        // Execute destination userOp
        currentNonce = IKernel(address(account)).getNonce();
        console2.log("Current nonce on BSC:", currentNonce);
        assertEq(destUserOp.nonce, currentNonce, "destUserOp nonce should equal current nonce on BSC");
        // executeXChainUserOp(destUserOp.nonce, srcUserOp, destUserOp, false);
    }

    /**
     * @dev Constructs a UserOperation that calls Kernel.setExecution(...) to enable
     *      the execValueBatch selector with {intentExecutor} and {intentValidator}.
     */
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
        // For cleanliness, set a distinct nonce just in case
        userOp.nonce = IKernel(address(account)).getNonce();
        return userOp;
    }

    /**
     * @dev Creates 2 userOps (src/dest), sets nonces, signs them cross-chain.
     */
    function prepareCrossChainUserOps() internal view returns (UserOperation memory, UserOperation memory) {
        bytes memory srcIntent = createIntent();
        bytes memory destIntent = createIntent();

        UserOperation memory srcUserOp = createUserOp(address(account), srcIntent);
        UserOperation memory destUserOp = createUserOp(address(account), destIntent);

        // Get current nonce on source chain (Polygon)
        uint256 srcNonce = IKernel(address(account)).getNonce();
        srcUserOp.nonce = srcNonce;
        destUserOp.nonce = 1;

        // Now compute hashes and sign with correct nonces
        bytes32 srcHash = intentValidator.getUserOpHash(srcUserOp, SOURCE_CHAIN_ID);
        bytes32 destHash = intentValidator.getUserOpHash(destUserOp, DEST_CHAIN_ID);

        // Cross-chain sign with correct nonces
        xSignCommon(srcHash, destHash, ownerPrivateKey, srcUserOp, destUserOp);

        // The "solver" step: append final solver callData to signatures
        srcUserOp.signature = abi.encodePacked(srcUserOp.signature, srcUserOp.callData);
        destUserOp.signature = abi.encodePacked(destUserOp.signature, destUserOp.callData);

        return (srcUserOp, destUserOp);
    }

    /**
     * @dev Verifies the signature of a userOp on the specified chain, then executes it.
     * We also handle the final prefixing and call handleOps to trigger the actual transaction.
     * @param userOp    The userOp to be validated and executed.
     * @param chainId   Which chain we’re “simulating” or “executing” on (source or dest).
     * @param amount    Amount of Ether to transfer in the batch.
     * @param recipient Who receives that Ether in the final callData.
     */
    function validateAndExecute(UserOperation memory userOp, uint256 chainId, uint256 amount, address recipient)
        internal
    {
        // Store current fork ID (if any)
        uint256 prevFork = vm.activeFork();

        // Switch to the Bsc if the chainId is the destination chain
        if (chainId == DEST_CHAIN_ID) {
            // BSC
            vm.selectFork(bscFork);
        } else if (chainId != SOURCE_CHAIN_ID) {
            revert("Unsupported chain ID");
        }

        // Ensure we're on the correct chain
        require(block.chainid == chainId, "Chain ID mismatch");

        // 1) Replace userOp.callData with execValueBatch
        userOp.callData = abi.encodeWithSelector(
            KernelIntentExecutor.execValueBatch.selector,
            _singleValueArray(amount),
            _singleAddressArray(recipient),
            _singleBytesArray(abi.encodeWithSignature("transfer(address,uint256)", recipient, amount))
        );

        // 2) Verify signature
        ValidationData result = intentValidator.validateUserOp(userOp, bytes32(0), 0);
        require(ValidationData.unwrap(result) == 0, "Validation failed");

        // 3) Prefix signature to route through the plugin validator
        userOp.signature = prefixSignature(userOp.signature, VALIDATION_PLUGIN_1);

        // 4) Execute
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;

        vm.expectEmit(false, true, true, false);
        emit IEntryPoint.UserOperationEvent(0, address(account), address(0), userOp.nonce, true, 0, 0);

        entryPoint.handleOps(ops, payable(ownerAddress));

        // Return to previous fork if there was one
        if (prevFork != 0) {
            vm.selectFork(prevFork);
        }
    }

    // --------------- Helper functions ---------------

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

    function testCrossChainValidationWithInvalidHash() public {
        // Create intents and ops
        bytes memory srcIntent = createIntent();
        bytes memory destIntent = createIntent();

        UserOperation memory srcUserOp = createUserOp(address(account), srcIntent);
        UserOperation memory destUserOp = createUserOp(address(account), destIntent);

        // Generate hashes
        bytes32 srcHash = intentValidator.getUserOpHash(srcUserOp, SOURCE_CHAIN_ID);
        bytes32 destHash = intentValidator.getUserOpHash(destUserOp, DEST_CHAIN_ID);
        bytes32 invalidHash = keccak256("invalid hash");

        // Create invalid hash list (using wrong hash)
        bytes[] memory srcHashList = new bytes[](2);
        srcHashList[0] = abi.encodePacked(uint16(XChainLib.XC_MARKER));
        srcHashList[1] = abi.encodePacked(invalidHash); // Wrong hash

        // Sign with correct hashes
        bytes32 xChainHash = keccak256(abi.encodePacked(srcHash, destHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, xChainHash.toEthSignedMessageHash());
        bytes memory signature = abi.encodePacked(r, s, v);

        // Set up source op with invalid hash list
        srcUserOp.callData = createCrossChainCallData(srcIntent, srcHashList);
        srcUserOp.signature = signature;

        // Validation should fail
        vm.chainId(SOURCE_CHAIN_ID);
        ValidationData result = intentValidator.validateUserOp(srcUserOp, bytes32(0), 0);
        assertTrue(ValidationData.unwrap(result) != 0, "Validation should fail with invalid hash");
    }

    // Helper functions
    function createIntent() internal pure returns (bytes memory) {
        return bytes(
            '{"fromAsset":{"address":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",'
            '"amount":{"value":"I4byb8EAAA=="},"chainId":{"value":"iQ=="}},'
            '"toStake":{"address":"0x1adB950d8bB3dA4bE104211D5AB038628e477fE6",'
            '"amount":{"value":"D0JA"},"chainId":{"value":"OA=="}}}'
        );
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

    function xSignCommon(
        bytes32 hash1,
        bytes32 hash2,
        uint256 privateKey,
        UserOperation memory sourceUserOp,
        UserOperation memory destUserOp
    ) internal pure {
        // Compare hash values to determine order
        bool shouldReverse = uint256(hash1) > uint256(hash2);

        bytes32 xChainHash =
            shouldReverse ? keccak256(abi.encodePacked(hash2, hash1)) : keccak256(abi.encodePacked(hash1, hash2));

        // Sign
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, xChainHash.toEthSignedMessageHash());
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build the cross-chain calldata values
        bytes memory placeholder = abi.encodePacked(uint16(XChainLib.XC_MARKER));
        bytes[] memory srcHashList = new bytes[](2);
        bytes[] memory destHashList = new bytes[](2);

        // Organize hash lists based on the comparison result
        if (shouldReverse) {
            // When hash1 > hash2, reverse order logic
            srcHashList[0] = abi.encodePacked(hash2);
            srcHashList[1] = placeholder;

            destHashList[0] = placeholder;
            destHashList[1] = abi.encodePacked(hash1);
        } else {
            // When hash1 < hash2, use the normal order logic
            srcHashList[0] = placeholder;
            srcHashList[1] = abi.encodePacked(hash2);

            destHashList[0] = abi.encodePacked(hash1);
            destHashList[1] = placeholder;
        }

        // Set the cross-chain calldata value after signing
        sourceUserOp.callData = createCrossChainCallData(sourceUserOp.callData, srcHashList);
        destUserOp.callData = createCrossChainCallData(destUserOp.callData, destHashList);

        sourceUserOp.signature = signature;
        destUserOp.signature = signature;
    }

    /**
     * @notice Creates cross-chain call data according to the linked hash specification.
     * @param intent The call data for the operation.
     * @param hashList The array of hash list entries (including the placeholder).
     * @return bytes The encoded cross-chain call data.
     */
    function createCrossChainCallData(bytes memory intent, bytes[] memory hashList)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory result = abi.encodePacked(
            uint16(XChainLib.XC_MARKER), // Marker (2 bytes)
            uint16(intent.length), // intentLength (2 bytes)
            intent,
            uint8(hashList.length) // hashListLength (1 byte)
        );

        for (uint256 i = 0; i < hashList.length; i++) {
            result = abi.encodePacked(result, hashList[i]);
        }
        return result;
    }

    function prefixSignature(bytes memory signature, uint256 prefixValue) internal pure returns (bytes memory) {
        require(prefixValue <= 2, "Invalid prefix value");
        require(signature.length > 4, "Invalid signature length");

        // Check if signature already has a prefix
        bytes4 existingPrefix = bytes4(bytes.concat(signature[0], signature[1], signature[2], signature[3]));
        bool hasPrefix = (existingPrefix == 0x00000000 || existingPrefix == 0x00000001 || existingPrefix == 0x00000002);

        // Get the actual signature without prefix
        bytes memory sigWithoutPrefix = hasPrefix ? slice(signature, 4, signature.length) : signature;

        bytes4 newPrefix;
        // VALIDATION_DEF_0 = 0;
        // VALIDATION_PLUGIN_1 = 1;
        // VALIATION_ENABLED_2 = 2;
        if (prefixValue == 0) newPrefix = 0x00000000;
        else if (prefixValue == 1) newPrefix = 0x00000001;
        else if (prefixValue == 2) newPrefix = 0x00000002;

        // Create new signature with desired prefix
        bytes memory prefixedSignature = new bytes(sigWithoutPrefix.length + 4);

        // Add new prefix
        for (uint256 i = 0; i < 4; i++) {
            prefixedSignature[i] = newPrefix[i];
        }
        // Add signature
        for (uint256 i = 0; i < sigWithoutPrefix.length; i++) {
            prefixedSignature[i + 4] = sigWithoutPrefix[i];
        }
        return prefixedSignature;
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
    function slice(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory result) {
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

        // Attach the "enable" prefix (0x00000002) plus the rest of the data
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

    // The IEntryPoint emits this after handleOps:
    event IEntryPointUserOpRevertReason(
        bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason
    );

    // Must match the IEntryPoint interface
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
