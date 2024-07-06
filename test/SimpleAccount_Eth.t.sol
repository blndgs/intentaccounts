// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
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

    function setUp() public {
        string memory privateKeyEnv = string(abi.encodePacked(_network, "ETHEREUM_PRIVATE_KEY"));
        string memory privateKeyString = vm.envString(privateKeyEnv);

        // Derive the Ethereum address from the private key
        _ownerPrivateKey = vm.parseUint(privateKeyString);
        _ownerAddress = vm.addr(_ownerPrivateKey);
        console2.log("Owner address:", _ownerAddress);

        // Create a VM instance for the ethereum fork
        string memory urlEnv = string(abi.encodePacked(_network, "ETHEREUM_RPC_URL"));
        _ethereumFork = vm.createSelectFork(vm.envString(urlEnv));
        console2.log("ChainID:", block.chainid);

        // Deploy the EntryPoint contract or use an existing one
        _entryPoint = EntryPoint(payable(ENTRYPOINT_V06));
        console2.log("EntryPoint deployed at:", address(_entryPoint));

        // Create a unique _salt for the account creation
        string memory _saltEnv = string(abi.encodePacked(_network, "ETHEREUM_SALT"));
        _salt = vm.envUint(_saltEnv);
        console2.log("Salt:", _salt);

        uint256 startGas = gasleft();

        // Sync the _factory
        _factory = new IntentSimpleAccountFactory(_entryPoint);
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

    function generateSignature(UserOperation memory userOp, uint256 chainID, uint256 signerPrvKey) internal view returns (bytes memory) {
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
            signature: bytes(
                hex""
                )
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

        // entryPoint emits events
        vm.expectEmit(false, true, true, false, 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        emit IEntryPoint.UserOperationEvent(0/* ignore userOp hash */, address(_simpleAccount), address(0) /* paymaster */, userOp.nonce, true, 0, 0);
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

     /**
      * Tests wallet creation with user (counterfactual account's address)
      * Ether funding.
      */
    function testCreateNewWalletUserEtherFunding() public {
        // New owner without a smart account wallet
        uint ownerPrivateKey = 0x150c8f7379076d4d9244ed39a9bfba489f664760e37b71d1bd4f231c5662d62e;
        address walletOwner = 0xd219ceeC68dE386AF92551F9b08a9Aef8910C4EA;

        console2.log("walletOwner:", walletOwner);
        address account = _factory.getAddress(walletOwner, 0);
        console2.log("counterfactual address for new wallet:", account);

        uint codeSize = account.code.length;
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
        emit IEntryPoint.UserOperationEvent(0/* ignore userOp hash */, account, address(0) /* paymaster */, userOp.nonce, true, 0, 0);
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
        uint ownerPrivateKey = 0x150c8f7379076d4d9244ed39a9bfba489f664760e37b71d1bd4f231c5662d62e;
        address walletOwner = 0xd219ceeC68dE386AF92551F9b08a9Aef8910C4EA;

        console2.log("walletOwner:", walletOwner);
        address account = _factory.getAddress(walletOwner, 0);
        console2.log("counterfactual address for new wallet:", account);

        uint codeSize = account.code.length;
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
        emit IEntryPoint.UserOperationEvent(0/* ignore userOp hash */, account, address(0) /* paymaster */, userOp.nonce, true, 0, 0);
        _entryPoint.handleOps(userOps, payable(_ownerAddress));

        uint256 balanceAfter = account.balance;
        uint256 depositAfter = _entryPoint.balanceOf(account);

        assertEq(balanceBef, balanceAfter, "Account Balance should not have increased after execution");
        assertEq(depositAfter, 0, "Entrypoint account deposits should be zero");
    }
}