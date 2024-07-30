// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

//import "forge-std/Test.sol";
import "../src/IntentSimpleAccount.sol";
import "@account-abstraction/interfaces/IEntryPoint.sol";
import "@account-abstraction/core/EntryPoint.sol";
import "../src/IntentSimpleAccountFactory.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../src/IntentUserOperation.sol";
import "./TestSimpleAccountHelper.sol";

contract SimpleAccounEthereumTest is Test {
    using Strings for bytes32;
    using UserOperationLib for UserOperation;
    using TestSimpleAccountHelper for UserOperation;

    address public constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 _ethereumFork;

    using ECDSA for bytes32;

    IntentSimpleAccountFactory _factory;
    IntentSimpleAccount _simpleAccount;
    uint256 _salt;
    IEntryPoint _entryPoint;
    address _ownerAddress;
    uint256 _ownerPrivateKey;

    string _network;

    IERC20 constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 constant USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    address constant USDC_WHALE = 0x47ac0Fb4F2D84898e4D9E7b4DaB3C24507a6D503;

    ExtractorHelper extractor;

    function setUp() public {
        _network = "ETHEREUM";
        string memory privateKeyEnv = string(abi.encodePacked(_network, "_PRIVATE_KEY"));
        string memory privateKeyString = vm.envString(privateKeyEnv);

        // Derive the Ethereum address from the private key
        _ownerPrivateKey = vm.parseUint(privateKeyString);
        _ownerAddress = vm.addr(_ownerPrivateKey);
        console2.log("Owner address:", _ownerAddress);

        // Create a VM instance for the ethereum fork
        string memory urlEnv = string(abi.encodePacked(_network, "_RPC_URL"));
        _ethereumFork = vm.createSelectFork(vm.envString(urlEnv));
        console2.log("ChainID:", block.chainid);

        // Deploy the EntryPoint contract or use an existing one
        _entryPoint = EntryPoint(payable(ENTRYPOINT_V06));
        console2.log("EntryPoint deployed at:", address(_entryPoint));

        // Create a unique _salt for the account creation
        string memory _saltEnv = string(abi.encodePacked(_network, "_SALT"));
        _salt = vm.envUint(_saltEnv);
        console2.log("Salt:", _salt);

        uint256 startGas = gasleft();

        // Sync the _factory with the chain factory address
        string memory factoryAddressEnv = string(abi.encodePacked(_network, "_SIMPLE_INTENT_FACTORY_ADDRESS"));
        address factoryAddress = vm.envAddress(factoryAddressEnv);
        console2.log("factory Address", factoryAddress);

        _factory = IntentSimpleAccountFactory(factoryAddress);
        console2.log("IntentSimpleAccountFactory synced at:", address(_factory));
        uint256 endGas = gasleft();
        console2.log("Gas used for Factory sync: ", startGas - endGas);
        startGas = endGas;

        // Create an account
        _simpleAccount = _factory.createAccount(_ownerAddress, _salt);
        console2.log("_SimpleAccount deployed at:", address(_simpleAccount));
        vm.deal(address(_simpleAccount), 1e30);

        // fund account with USDC
        uint256 amount = 10000000000; // 1000 USDC
        vm.prank(USDC_WHALE);
        USDC.transfer(address(_simpleAccount), amount);

        vm.startPrank(_ownerAddress);

        extractor = new ExtractorHelper();
    }

    function testSimpleAccountAddress() public {
        // verify the created account's address matches the expected counterfactual address
        address generatedAddress = _factory.getAddress(_ownerAddress, _salt);
        console2.log("Expected SimpleAccount address:", generatedAddress);
        console2.log("Actual SimpleAccount address:", address(_simpleAccount));
        assertEq(address(_simpleAccount), generatedAddress, "Account address does not match expected address");
    }

    // Original function from the SimpleAccount contract
    function getUserOpHash(UserOperation calldata userOp, uint256 chainID) public pure returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), ENTRYPOINT_V06, chainID));
    }

    // Wrapper around the original function to create a call context
    function getOrigUserOpHash(UserOperation memory userOp, uint256 chainID) internal view returns (bytes32) {
        return this.getUserOpHash(userOp, chainID);
    }

    function generateSignature(UserOperation memory userOp, uint256 chainID) internal view returns (bytes memory) {
        return generateSignature(userOp, chainID, _ownerPrivateKey);
    }

    function generateSignature(UserOperation memory userOp, uint256 chainID, uint256 signerPrvKey)
        internal
        view
        returns (bytes memory)
    {
        bytes32 userOpHash = _simpleAccount.getUserOpHash(userOp, chainID);

        // Sign the hash with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrvKey, userOpHash.toEthSignedMessageHash());

        // Combine (v, r, s) into a signature
        bytes memory signature = abi.encodePacked(r, s, v);

        return signature;
    }

    function verifySignature(UserOperation memory userOp) internal returns (uint256) {
        // not supplying the userOpHash as _validateSignature calls for the Intent version
        uint256 result = _simpleAccount.validateSignature(userOp, bytes32(0));
        assertEq(result, 0, "Signature is not valid for the userOp");

        return result;
    }

    // Test userOp validation for a vanilla Ethereum operation
    // userOp has no initCode, callData, or paymaster
    // _simpleAccount is already deployed
    function testValidateEtherVanillaOp() public {
        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: address(_simpleAccount),
            nonce: 0x0,
            initCode: bytes(hex""),
            callData: bytes(hex""),
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = _simpleAccount.getNonce();
        console2.log("nonce:", userOp.nonce);

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);
        console2.log("signature:"); // 65 bytes or 130 hex characters. ECDSA signature
        console2.logBytes(userOp.signature);

        verifySignature(userOp);
    }

    function testValidateExecute_SolverNative() public {
        console2.log("sender:", address(_simpleAccount));

        uint256 balanceEthBef = address(_simpleAccount).balance;
        uint256 usdcBalanceBefore = USDC.balanceOf(address(_simpleAccount));
        uint256 usdtBalanceBefore = USDT.balanceOf(address(_simpleAccount));
        console2.log("USDC Balance Before:", usdcBalanceBefore);
        console2.log("USDT Balance Before:", usdtBalanceBefore);

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: address(_simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                "{\"from\":{\"type\":\"TOKEN\",\"address\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"amount\":\"0.8\",\"chainId\":\"1\"},\"to\":{\"type\":\"TOKEN\",\"address\":\"0xdac17f958d2ee523a2206206994597c13d831ec7\",\"chainId\":\"1\"}}"
            ),
            callGasLimit: 800000,
            verificationGasLimit: 500000,
            preVerificationGas: 500000,
            maxFeePerGas: 0, // Sponsored by the Bundler
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = _simpleAccount.getNonce();
        console2.log("nonce:", userOp.nonce);

        // 2. SDK signs the intent userOp
        userOp.signature = generateSignature(userOp, block.chainid);
        console2.log("signature:"); // 65 bytes or 130 hex characters. ECDSA signature
        console2.logBytes(userOp.signature);

        // 3. SDK submits to Bundler...
        // 4. Bundler submits userOp to the Solver

        // 5. Solver solves Intent userOp
        userOp.signature = bytes(
            abi.encodePacked(
                userOp.signature, // 65 bytes or 130 hex characters. ECDSA signature
                userOp.callData // Intent JSON
            )
        );
        userOp.callData = bytes(
            hex"18dfb3c7000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff00000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000128d9627aa4000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7869584cd00000000000000000000000010000000000000000000000000000000000000110000000000000000000000000000000015b9ca29df2cd4b929d481fcb4ab9642000000000000000000000000000000000000000000000000"
        );
        console2.log("intent signature:");
        console2.logBytes(userOp.signature);

        // 6. Bundler submits solved userOp on-chain

        verifySignature(userOp);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        TestSimpleAccountHelper.printUserOperation(userOp);

        // entryPoint emits events
        vm.expectEmit(false, true, true, false, 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        emit IEntryPoint.UserOperationEvent(
            0, /* ignore userOp hash */ address(_simpleAccount), address(0), /* paymaster */ userOp.nonce, true, 0, 0
        );
        // 7. entryPoint executes the intent userOp
        _entryPoint.handleOps(userOps, payable(_ownerAddress));

        uint256 balanceEthAfter = address(_simpleAccount).balance;
        // print the balance of the contract
        console2.log("Before, after Balance of SimpleAccount in Wei:", balanceEthBef, balanceEthAfter);
        assertEq(balanceEthAfter, balanceEthBef, "ETH Balance should have remained the same");

        uint256 usdcBalanceAfter = USDC.balanceOf(address(_simpleAccount));
        uint256 usdtBalanceAfter = USDT.balanceOf(address(_simpleAccount));

        console2.log("USDC Balance After:", usdcBalanceAfter);
        console2.log("USDT Balance After:", usdtBalanceAfter);

        assertLt(usdcBalanceAfter, usdcBalanceBefore, "USDC balance should decrease");
        assertGt(usdtBalanceAfter, usdtBalanceBefore, "USDT balance should increase");
        assertEq(usdcBalanceBefore - usdcBalanceAfter, 1 * 1e6, "Should have spent 1000 USDC");
    }

    /// @dev Returns a copy of `subject` sliced from `start` to `end` (exclusive).
    /// `start` and `end` are byte offsets.
    function slice(string memory subject, uint256 start, uint256 end)
    internal
    pure
    returns (string memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let subjectLength := mload(subject)
            if iszero(gt(subjectLength, end)) { end := subjectLength }
            if iszero(gt(subjectLength, start)) { start := subjectLength }
            if lt(start, end) {
                result := mload(0x40)
                let resultLength := sub(end, start)
                mstore(result, resultLength)
                subject := add(subject, start)
                let w := not(0x1f)
            // Copy the `subject` one word at a time, backwards.
                for { let o := and(add(resultLength, 0x1f), w) } 1 {} {
                    mstore(add(result, o), mload(add(subject, o)))
                    o := add(o, w) // `sub(o, 0x20)`.
                    if iszero(o) { break }
                }
            // Zeroize the slot after the string.
                mstore(add(add(result, 0x20), resultLength), 0)
            // Allocate memory for the length and the bytes,
            // rounded up to a multiple of 32.
                mstore(0x40, add(result, and(add(resultLength, 0x3f), w)))
            }
        }
    }

    function testCrossChainUserOp() public {
        UserOperation memory sourceEthOp = UserOperation({
            sender: 0xc291efDc1a6420CBB226294806604833982Ed24d,
            nonce: 161,
            initCode: new bytes(0),
            callData: hex"18dfb3c7000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff00000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000128d9627aa4000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7869584cd00000000000000000000000010000000000000000000000000000000000000110000000000000000000000000000000015b9ca29df2cd4b929d481fcb4ab9642000000000000000000000000000000000000000000000000",
            callGasLimit: 800000,
            verificationGasLimit: 500000,
            preVerificationGas: 500000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: new bytes(0),
            signature: hex"fe050651afae2c8d5b87a4f2995bbc77c6efba4eb0a801bca371bfccd7dc551009f829eb0c17836968f49210a3e3a5cc955f40e3b66f512d956302d9a963bb081b7b2266726f6d223a7b2274797065223a22544f4b454e222c2261646472657373223a22307845656565654565656545654565654565456545656545454565656565456565656565656545456545222c22616d6f756e74223a22302e38222c22636861696e4964223a2231227d2c22746f223a7b2274797065223a22544f4b454e222c2261646472657373223a22307864616331376639353864326565353233613232303632303639393435393763313364383331656337222c22636861696e4964223a2231227d7d"
        });

        UserOperation memory destPolygonOp = UserOperation({
            sender: 0xc291efDc1a6420CBB226294806604833982Ed24d,
            nonce: 1,
            initCode: new bytes(0),
            callData: hex"18dfb3c7000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff00000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000128d9627aa4000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000f4240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7869584cd00000000000000000000000010000000000000000000000000000000000000110000000000000000000000000000000015b9ca29df2cd4b929d481fcb4ab9642000000000000000000000000000000000000000000000000",
            callGasLimit: 800000,
            verificationGasLimit: 500000,
            preVerificationGas: 500000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: new bytes(0),
            signature: hex"fe050651afae2c8d5b87a4f2995bbc77c6efba4eb0a801bca371bfccd7dc551009f829eb0c17836968f49210a3e3a5cc955f40e3b66f512d956302d9a963bb081b7b2266726f6d223a7b2274797065223a22544f4b454e222c2261646472657373223a22307845656565654565656545654565654565456545656545454565656565456565656565656545456545222c22616d6f756e74223a22302e38222c22636861696e4964223a2231227d2c22746f223a7b2274797065223a22544f4b454e222c2261646472657373223a22307864616331376639353864326565353233613232303632303639393435393763313364383331656337222c22636861696e4964223a2231227d7d"
        });

        UserOperation memory combinedOp = sourceEthOp.combineUserOps(destPolygonOp);

        // Simulate sending combinedOp to the destination chain
        // Convert memory to calldata by making an external call
        // Call the ExtractorHelper contract directly
        try ExtractorHelper(address(extractor)).extractDestUserOp(combinedOp) returns (UserOperation memory extractedDestOp) {
            // Your existing assertions
            assertEq(extractedDestOp.sender, destPolygonOp.sender);
            assertEq(extractedDestOp.nonce, destPolygonOp.nonce);
            assertEq(extractedDestOp.callGasLimit, destPolygonOp.callGasLimit);
            assertEq(extractedDestOp.verificationGasLimit, destPolygonOp.verificationGasLimit);
            assertEq(extractedDestOp.preVerificationGas, destPolygonOp.preVerificationGas);
            assertEq(extractedDestOp.maxFeePerGas, destPolygonOp.maxFeePerGas);
            assertEq(extractedDestOp.maxPriorityFeePerGas, destPolygonOp.maxPriorityFeePerGas);

            // Optional: Log the extracted UserOperation for debugging
            console2.log("Extracted UserOperation:");
            console2.log("  sender:", extractedDestOp.sender);
            console2.log("  nonce:", extractedDestOp.nonce);
            console2.log("  callGasLimit:", extractedDestOp.callGasLimit);
            console2.log("  verificationGasLimit:", extractedDestOp.verificationGasLimit);
            console2.log("  preVerificationGas:", extractedDestOp.preVerificationGas);
            console2.log("  maxFeePerGas:", extractedDestOp.maxFeePerGas);
            console2.log("  maxPriorityFeePerGas:", extractedDestOp.maxPriorityFeePerGas);
            console2.log("  callData length:", extractedDestOp.callData.length);
        } catch Error(string memory reason) {
            console2.log("Error caught:", reason);
            revert(reason);
        } catch (bytes memory lowLevelData) {
            console2.log("Low-level error caught");
            console2.logBytes(lowLevelData);
            revert("Low-level error in extractDestUserOp");
        }
    }

    function testValidateExecute_Squid() public {
        _simpleAccount = IntentSimpleAccount(payable(0xc291efDc1a6420CBB226294806604833982Ed24d));
        console2.log("sender:", address(_simpleAccount));

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: address(_simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                hex"846a1bc6000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee00000000000000000000000000000000000000000000000000038d7ea4c6800000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000340000000000000000000000000000000000000000000000000000000000000038000000000000000000000000000000000000000000000000000000000000003c000000000000000000000000000000000000000000000000000000000000004200000000000000000000000008af962c13411f10214d5b50e4beacec42f37c537000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000200000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc45000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000e404e45aaf000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000ce16f69375520ab01377ce7b88f5ba8c48f8d66600000000000000000000000000000000000000000000000000038d7ea4c6800000000000000000000000000000000000000000000000000000000000003139eb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000455534443000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007506f6c79676f6e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a307863653136463639333735353230616230313337376365374238386635424138433438463844363636000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bc00000000000000000000000000000000000000000000000000000000000000040000000000000000000000000c182aa0ecb24a674c00c76ce8f1761cc5a10611c000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001e000000000000000000000000000000000000000000000000000000000000003600000000000000000000000000000000000000000000000000000000000000580000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000009200000000000000000000000000000000000000000000000000000000000000a8000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000750e4c4984a9e0f12978ea6742bc1c5d248f40ed0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000750e4c4984a9e0f12978ea6742bc1c5d248f40ed000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000f5b509bb0909a69b1c207e495f687a596c168e120000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000750e4c4984a9e0f12978ea6742bc1c5d248f40ed00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f5b509bb0909a69b1c207e495f687a596c168e12000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000e4bc651188000000000000000000000000750e4c4984a9e0f12978ea6742bc1c5d248f40ed0000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa84174000000000000000000000000ea749fd6ba492dbc14c24fe8a3d08769229b896c00000000000000000000000000000000000000000000000000000190ef2b928f0000000000000000000000000000000000000000000000000000000000316cbb0000000000000000000000000000000000000000000000000000000000311b830000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000750e4c4984a9e0f12978ea6742bc1c5d248f40ed000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000010000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa84174000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000044095ea7b300000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc4500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa841740000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000068b3465833fb72a70ecdf485e0e4c7bd8665fc45000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000e404e45aaf0000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa841740000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf127000000000000000000000000000000000000000000000000000000000000001f4000000000000000000000000ea749fd6ba492dbc14c24fe8a3d08769229b896c000000000000000000000000000000000000000000000000000000000031679a00000000000000000000000000000000000000000000000057845262fe0e5f2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa84174000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf1270000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000242e1a7d4d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf127000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c182aa0ecb24a674c00c76ce8f1761cc5a10611c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ),
            callGasLimit: 800000,
            verificationGasLimit: 500000,
            preVerificationGas: 500000,
            maxFeePerGas: 0, // Sponsored by the Bundler
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = _simpleAccount.getNonce();
        console2.log("nonce:", userOp.nonce);

        // 2. SDK signs the intent userOp
        userOp.signature = generateSignature(userOp, block.chainid);
        console2.log("signature:"); // 65 bytes or 130 hex characters. ECDSA signature
        console2.logBytes(userOp.signature);
        verifySignature(userOp);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        TestSimpleAccountHelper.printUserOperation(userOp);

        // entryPoint emits events
        vm.expectEmit(false, true, true, false, 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        emit IEntryPoint.UserOperationEvent(
            0, /* ignore userOp hash */ address(_simpleAccount), address(0), /* paymaster */ userOp.nonce, true, 0, 0
        );
        // 7. entryPoint executes the intent userOp
        _entryPoint.handleOps(userOps, payable(_ownerAddress));
    }

    /**
     * Tests wallet creation with user (counterfactual account's address)
     * Ether funding.
     */
    function testCreateNewWalletUserEtherFunding() public {
        // New owner without a smart account wallet
        uint256 ownerPrivateKey = 0x150c8f7379076d4d9244ed39a9bfba489f664760e37b71d1bd4f231c5662d62e;
        address walletOwner = 0xd219ceeC68dE386AF92551F9b08a9Aef8910C4EA;

        console2.log("walletOwner:", walletOwner);
        address account = _factory.getAddress(walletOwner, 0);
        console2.log("counterfactual address for new wallet:", account);

        uint256 codeSize = account.code.length;
        assertEq(codeSize, 0, "Account should not be deployed yet");

        // **************************************************************
        // Non-zero gas userOp, user funds it.
        // In this case the account has deposited in the EntryPoint
        // **************************************************************
        vm.deal(account, 10 ether);
        uint256 balanceBef = account.balance;
        assertEq(balanceBef, 10 ether);

        uint256 depositBef = _entryPoint.balanceOf(account);
        assertEq(depositBef, 0, "Entrypoint account deposits is 0 before execution");

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: account,
            nonce: 0,
            // <Account factory address> + createAccount(owner<0xd219ceeC68dE386AF92551F9b08a9Aef8910C4EA>, salt:0) calldata
            initCode: TestSimpleAccountHelper.getInitCode(_factory, walletOwner, 0),
            callData: bytes(hex""),
            callGasLimit: 800000,
            verificationGasLimit: 628384,
            preVerificationGas: 626688,
            maxFeePerGas: 65536, // Non zero value requires ETH balance in account
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        userOp.signature = generateSignature(userOp, block.chainid, ownerPrivateKey);
        console2.log("signature:"); // 65 bytes or 130 hex characters. ECDSA signature
        console2.logBytes(userOp.signature);

        // entryPoint emits successful userOp execution events
        vm.expectEmit(false, true, true, false, 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        emit IEntryPoint.UserOperationEvent(
            0, /* ignore userOp hash */ account, address(0), /* paymaster */ userOp.nonce, true, 0, 0
        );
        _entryPoint.handleOps(userOps, payable(_ownerAddress));

        uint256 balanceAfter = account.balance;
        uint256 depositAfter = _entryPoint.balanceOf(account);

        assertLt(balanceAfter, balanceBef, "Balance of SimpleAccount should have decreased after execution");
        assertGt(depositAfter, depositBef, "Entrypoint account deposits should have increased after execution");
    }

    /**
     * Tests sponsored wallet creation by bundler.
     */
    function testCreateNewWalletFundingByBundler() public {
        // New owner without a smart account wallet
        uint256 ownerPrivateKey = 0x150c8f7379076d4d9244ed39a9bfba489f664760e37b71d1bd4f231c5662d62e;
        address walletOwner = 0xd219ceeC68dE386AF92551F9b08a9Aef8910C4EA;

        console2.log("walletOwner:", walletOwner);
        address account = _factory.getAddress(walletOwner, 0);
        console2.log("counterfactual address for new wallet:", account);

        uint256 codeSize = account.code.length;
        assertEq(codeSize, 0, "Account should not be deployed yet");

        uint256 balanceBef = account.balance;
        uint256 depositBef = _entryPoint.balanceOf(account);
        assertEq(depositBef, 0, "Entrypoint account deposits is 0 before execution");

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: account,
            nonce: 0,
            // <Account factory address> + createAccount(owner<0xd219ceeC68dE386AF92551F9b08a9Aef8910C4EA>, salt:0) calldata
            initCode: TestSimpleAccountHelper.getInitCode(_factory, walletOwner, 0),
            callData: bytes(hex""),
            callGasLimit: 800000,
            verificationGasLimit: 628384,
            preVerificationGas: 626688,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        userOp.signature = generateSignature(userOp, block.chainid, ownerPrivateKey);
        console2.log("signature:"); // 65 bytes or 130 hex characters. ECDSA signature
        console2.logBytes(userOp.signature);

        // entryPoint emits successful userOp execution events
        vm.expectEmit(false, true, true, false, 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        emit IEntryPoint.UserOperationEvent(
            0, /* ignore userOp hash */ account, address(0), /* paymaster */ userOp.nonce, true, 0, 0
        );
        _entryPoint.handleOps(userOps, payable(_ownerAddress));

        uint256 balanceAfter = account.balance;
        uint256 depositAfter = _entryPoint.balanceOf(account);

        assertEq(balanceBef, balanceAfter, "Account Balance should not have increased after execution");
        assertEq(depositAfter, 0, "Entrypoint account deposits should be zero");
    }

    /**
     * Gas Cost Comparison Report
     *
     * This report compares the gas costs in the following 3 tests of three execution APIs:
     * 1. execute
     * 2. executeBatch
     * 3. execValueBatch
     *
     * Assumptions:
     * - Gas price: 30 gwei
     * - ETH price: $3,051.34 (9-Jul-2024)
     *
     * Results:
     * 1. execute:
     *    - Gas used: 235,974
     *    - Estimated Ethereum USD cost: $21.61
     *
     * 2. executeBatch:
     *    - Gas used: 236,018
     *    - Cost in USD: $21.62
     *    - Difference from execute: +44 gas (+$0.01)
     *    - Percentage increase: 0.019%
     *
     * 3. execValueBatch:
     *    - Gas used: 239,214
     *    - Cost in USD: $21.91
     *    - Difference from execute: +3,240 gas (+$0.30)
     *    - Percentage increase: 1.37%
     *
     * Analysis:
     * - The most flexible API, execValueBatch, is the most expensive, using 3,240 more gas than execute.
     * - The Ethereum USD estimated cost difference between execValueBatch and execute is approximately
     * - $0.30 per transaction.
     * - executeBatch is only marginally more expensive than execute (+$0.01).
     *
     * Recommendation:
     * Given the minimal cost difference, using only execValueBatch in the Kernel wallet
     * for all operations could be beneficial:
     * 1. It simplifies the API, reducing complexity for users (separate execution API for Intents).
     * 2. It provides maximum flexibility for all types of transactions.
     * 3. The additional cost ($0.30 per transaction) is likely negligible for most use cases.
     * 4. Removing execute and executeBatch could slightly reduce contract size and deployment costs.
     *
     * Unless the application is extremely gas-sensitive or processes an enormous volume of transactions,
     * the benefits of a simplified and more flexible API likely outweigh the small increase in gas costs.
     */
    function testLidoDeposit_ExecValueBatch() public {
        uint256 balanceEthBef = address(_simpleAccount).balance;

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: address(_simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                "{\"from\":{\"type\":\"TOKEN\",\"address\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"amount\":\"0.8\",\"chainId\":\"1\"},\"to\":{\"type\":\"TOKEN\",\"address\":\"0xdac17f958d2ee523a2206206994597c13d831ec7\",\"chainId\":\"1\"}}"
            ),
            callGasLimit: 800000,
            verificationGasLimit: 500000,
            preVerificationGas: 500000,
            maxFeePerGas: 0, // Sponsored by the Bundler
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = _simpleAccount.getNonce();

        // 2. SDK signs the intent userOp
        userOp.signature = generateSignature(userOp, block.chainid);

        // 3. SDK submits to Bundler...
        // 4. Bundler submits userOp to the Solver

        // 5. Solver solves Intent userOp
        userOp.signature = bytes(
            abi.encodePacked(
                userOp.signature, // 65 bytes or 130 hex characters. ECDSA signature
                userOp.callData // Intent JSON
            )
        );
        userOp.callData = bytes(
            hex"d6f6b170000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000ae7ab96520de3a18e5e111b5eaab095312d7fe84000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024a1903eab000000000000000000000000ff6f893437e88040ffb70ce6aeff4ccbf8dc19a400000000000000000000000000000000000000000000000000000000"
        );

        // 6. Bundler submits solved userOp on-chain
        verifySignature(userOp);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        // entryPoint emits events
        vm.expectEmit(false, true, true, false, 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        emit IEntryPoint.UserOperationEvent(
            0, /* ignore userOp hash */ address(_simpleAccount), address(0), /* paymaster */ userOp.nonce, true, 0, 0
        );
        // 7. entryPoint executes the intent userOp
        _entryPoint.handleOps(userOps, payable(_ownerAddress));

        uint256 balanceEthAfter = address(_simpleAccount).balance;
        assertEq(balanceEthAfter, balanceEthBef - 1, "ETH Balance should have less the Lido deposited value");
    }

    function testLidoDeposit_PlainExecute() public {
        uint256 balanceEthBef = address(_simpleAccount).balance;

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: address(_simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                "{\"from\":{\"type\":\"TOKEN\",\"address\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"amount\":\"0.8\",\"chainId\":\"1\"},\"to\":{\"type\":\"TOKEN\",\"address\":\"0xdac17f958d2ee523a2206206994597c13d831ec7\",\"chainId\":\"1\"}}"
            ),
            callGasLimit: 800000,
            verificationGasLimit: 500000,
            preVerificationGas: 500000,
            maxFeePerGas: 0, // Sponsored by the Bundler
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = _simpleAccount.getNonce();

        // 2. SDK signs the intent userOp
        userOp.signature = generateSignature(userOp, block.chainid);

        // 3. SDK submits to Bundler...
        // 4. Bundler submits userOp to the Solver

        // 5. Solver solves Intent userOp
        userOp.signature = bytes(
            abi.encodePacked(
                userOp.signature, // 65 bytes or 130 hex characters. ECDSA signature
                userOp.callData // Intent JSON
            )
        );
        userOp.callData = bytes(
            hex"b61d27f6000000000000000000000000ae7ab96520de3a18e5e111b5eaab095312d7fe84000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000024a1903eab000000000000000000000000ff6f893437e88040ffb70ce6aeff4ccbf8dc19a400000000000000000000000000000000000000000000000000000000"
        );

        // 6. Bundler submits solved userOp on-chain
        verifySignature(userOp);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        // entryPoint emits events
        vm.expectEmit(false, true, true, false, 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        emit IEntryPoint.UserOperationEvent(
            0, /* ignore userOp hash */ address(_simpleAccount), address(0), /* paymaster */ userOp.nonce, true, 0, 0
        );
        // 7. entryPoint executes the intent userOp
        _entryPoint.handleOps(userOps, payable(_ownerAddress));

        uint256 balanceEthAfter = address(_simpleAccount).balance;
        assertEq(balanceEthAfter, balanceEthBef - 1, "ETH Balance should have less the Lido deposited value");
    }

    function testLidoDeposit_ExecuteBatch() public {
        uint256 balanceEthBef = address(_simpleAccount).balance;

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: address(_simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                "{\"from\":{\"type\":\"TOKEN\",\"address\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"amount\":\"0.8\",\"chainId\":\"1\"},\"to\":{\"type\":\"TOKEN\",\"address\":\"0xdac17f958d2ee523a2206206994597c13d831ec7\",\"chainId\":\"1\"}}"
            ),
            callGasLimit: 800000,
            verificationGasLimit: 500000,
            preVerificationGas: 500000,
            maxFeePerGas: 0, // Sponsored by the Bundler
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = _simpleAccount.getNonce();

        // 2. SDK signs the intent userOp
        userOp.signature = generateSignature(userOp, block.chainid);

        // 3. SDK submits to Bundler...
        // 4. Bundler submits userOp to the Solver

        // 5. Solver solves Intent userOp
        userOp.signature = bytes(
            abi.encodePacked(
                userOp.signature, // 65 bytes or 130 hex characters. ECDSA signature
                userOp.callData // Intent JSON
            )
        );
        userOp.callData = bytes(
            hex"b61d27f6000000000000000000000000ae7ab96520de3a18e5e111b5eaab095312d7fe84000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000024a1903eab000000000000000000000000ff6f893437e88040ffb70ce6aeff4ccbf8dc19a400000000000000000000000000000000000000000000000000000000"
        );

        // 6. Bundler submits solved userOp on-chain
        verifySignature(userOp);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        // entryPoint emits events
        vm.expectEmit(false, true, true, false, 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        emit IEntryPoint.UserOperationEvent(
            0, /* ignore userOp hash */ address(_simpleAccount), address(0), /* paymaster */ userOp.nonce, true, 0, 0
        );
        // 7. entryPoint executes the intent userOp
        _entryPoint.handleOps(userOps, payable(_ownerAddress));

        uint256 balanceEthAfter = address(_simpleAccount).balance;
        assertEq(balanceEthAfter, balanceEthBef - 1, "ETH Balance should have less the Lido deposited value");
    }
}

contract ExtractorHelper {
    function extractDestUserOp(UserOperation calldata combinedOp) external view returns (UserOperation memory) {
        console2.log("Entered extractDestUserOp");
        console2.log("combinedOp.callData length:", combinedOp.callData.length);

        (uint256 sourceCallDataLength, bytes memory packedDestOpData) = extractPackedData(combinedOp.callData);
        console.log("sourceCallDataLength:", sourceCallDataLength);

        IntentSimpleAccount.PackedUserOp memory packedDestOp = decodePackedUserOp(packedDestOpData);

        return unpackUserOp(packedDestOp);
    }

    function extractPackedData(bytes calldata callData) internal pure returns (uint256, bytes memory) {
        require(callData.length >= 32, "Invalid callData length");

        uint256 sourceCallDataLength = uint256(bytes32(callData[:32]));
        console2.log("sourceCallDataLength:", sourceCallDataLength);

        require(callData.length > 32 + sourceCallDataLength, "Invalid callData format");

        bytes memory packedDestOpData = callData[32 + sourceCallDataLength:];
        console2.log("packedDestOpData length:", packedDestOpData.length);

        require(packedDestOpData.length > 0, "No packed destination UserOp found");

        console2.log("packedDestOpData:");
        console2.logBytes(packedDestOpData);

        return (sourceCallDataLength, packedDestOpData);
    }

    function decodePackedUserOp(bytes memory packedDestOpData) internal view returns (IntentSimpleAccount.PackedUserOp memory) {
        console2.log("Attempting to decode PackedUserOp");

        IntentSimpleAccount.PackedUserOp memory packedDestOp = abi.decode(packedDestOpData, (IntentSimpleAccount.PackedUserOp));

        console2.log("Decoding successful");
        logPackedUserOp(packedDestOp);

        return packedDestOp;
    }

    function logPackedUserOp(IntentSimpleAccount.PackedUserOp memory packedDestOp) internal view {
        console2.log("Decoded packedDestOp:");
        console2.log("  sender:", packedDestOp.sender);
        console2.log("  nonce:", packedDestOp.nonce);
        console2.log("  callGasLimit:", packedDestOp.callGasLimit);
        console2.log("  verificationGasLimit:", packedDestOp.verificationGasLimit);
        console2.log("  preVerificationGas:", packedDestOp.preVerificationGas);
        console2.log("  maxFeePerGas:", packedDestOp.maxFeePerGas);
        console2.log("  maxPriorityFeePerGas:", packedDestOp.maxPriorityFeePerGas);
        console2.log("  callData length:", packedDestOp.callData.length);
    }

    function unpackUserOp(IntentSimpleAccount.PackedUserOp memory packedOp) internal pure returns (UserOperation memory) {
        console2.log("Unpacking UserOperation");
        return UserOperation({
            sender: packedOp.sender,
            nonce: packedOp.nonce,
            initCode: new bytes(0),
            callData: packedOp.callData,
            callGasLimit: packedOp.callGasLimit,
            verificationGasLimit: packedOp.verificationGasLimit,
            preVerificationGas: packedOp.preVerificationGas,
            maxFeePerGas: packedOp.maxFeePerGas,
            maxPriorityFeePerGas: packedOp.maxPriorityFeePerGas,
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });
    }
}



