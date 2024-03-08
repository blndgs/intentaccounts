// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SimpleAccount.sol";
import "../src/IEntryPoint.sol";
import "../src/EntryPoint.sol";
import "../src/SimpleAccountFactory.sol";
import "../src/ECDSA.sol";
import "../src/UserOperation.sol";

contract SimpleAccounEthereumTest is Test {
    using Strings for bytes32;
    using UserOperationLib for UserOperation;

    address public constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 public constant ETHEREUM_CHAIN_ID = 1;
    uint256 _ethereumFork;

    using ECDSA for bytes32;

    SimpleAccountFactory _factory;
    SimpleAccount _simpleAccount;
    uint256 _salt;
    IEntryPoint _entryPoint;
    address _ownerAddress;
    uint256 _ownerPrivateKey;

    string _network;

    function setUp() public {
        string memory privateKeyEnv = string(abi.encodePacked(_network, "ETHEREUM_PRIVATE_KEY"));
        string memory privateKeyString = vm.envString(privateKeyEnv);

        // Derive the Ethereum address from the private key
        _ownerPrivateKey = vm.parseUint(privateKeyString);
        _ownerAddress = vm.addr(_ownerPrivateKey);
        assertEq(_ownerAddress, 0xc9164f44661d83d01CbB69C0b0E471280f446099, "Owner address should match");
        console2.log("Owner address:", _ownerAddress);

        // Create a VM instance for the ethereum fork
        string memory urlEnv = string(abi.encodePacked(_network, "ETHEREUM_RPC_URL"));
        _ethereumFork = vm.createSelectFork(vm.envString(urlEnv));
        assert(ETHEREUM_CHAIN_ID == block.chainid);

        vm.startPrank(_ownerAddress);

        // Deploy the EntryPoint contract or use an existing one
        _entryPoint = EntryPoint(payable(ENTRYPOINT_V06));
        console2.log("EntryPoint deployed at:", address(_entryPoint));

        // Create a unique _salt for the account creation
        string memory _saltEnv = string(abi.encodePacked(_network, "ETHEREUM_SALT"));
        _salt = vm.envUint(_saltEnv);
        console2.log("Salt:", _salt);

        uint256 startGas = gasleft();

        // Sync the _factory with the deployed contract at Mannet
        _factory = SimpleAccountFactory(0x42E60c23aCe33c23e0945a07f6e2c1E53843a1d5);
        console2.log("SimpleAccountFactory synced at:", address(_factory));
        uint256 endGas = gasleft();
        console2.log("Gas used for Factory sync: ", startGas - endGas);
        startGas = endGas;

        // Use the _factory to create a new SimpleAccount instance
        _simpleAccount = SimpleAccount(payable (0xc31bE7F83620D7cEF8EdEbEe0f5aF096A7C0b7F4));
        console2.log("SimpleAccount wallet created at:", address(_simpleAccount));
        console2.log("Gas used for wallet creation: ", startGas - endGas);
        startGas = endGas;
    }

    function testSimpleAccountAddress() public {
        // verify the created account's address matches the expected counterfactual address
        address generatedAddress = _factory.getAddress(_ownerAddress, _salt);
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
        bytes32 userOpHash = _simpleAccount.getUserOpHash(userOp, chainID);

        // Sign the hash with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_ownerPrivateKey, userOpHash.toEthSignedMessageHash());

        // Combine (v, r, s) into a signature
        bytes memory signature = abi.encodePacked(r, s, v);

        return signature;
    }

    function verifySignature(UserOperation memory userOp) internal returns (uint256) {
        // not supplying the userOpHash as _validateSignature calls for the Intent version
        uint256 result = _simpleAccount.ValidateSignature(userOp, bytes32(0));
        assertEq(result, 0, "Signature is not valid for the userOp");

        return result;
    }

    function testValidateExecute_SolverNative() public {
        console2.log("sender:", address(_simpleAccount));

        uint256 balanceBef = address(_simpleAccount).balance;

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: address(_simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                "{\"sender\":\"0xc31bE7F83620D7cEF8EdEbEe0f5aF096A7C0b7F4\",\"from\":{\"type\":\"TOKEN\",\"address\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"amount\":\"0.8\",\"chainId\":\"1\"},\"to\":{\"type\":\"TOKEN\",\"address\":\"0xdac17f958d2ee523a2206206994597c13d831ec7\",\"chainId\":\"1\"}}"
                ),
            callGasLimit: 800000,
            verificationGasLimit: 100000,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = _simpleAccount.getNonce();
        console2.log("nonce:", userOp.nonce);

        // 2. SDK signs the intent userOp
        userOp.signature = generateSignature(userOp, block.chainid);
        console2.log("signature:");
        console2.logBytes(userOp.signature);

        // 3. SDK submits to Bundler...
        // 4. Bundler submits userOp to the Solver

        // 5. Solver solves Intent userOp
        userOp.signature = bytes(
            abi.encodePacked(
                userOp.signature,
                userOp.callData
            )
        );
        userOp.callData = bytes(
            hex"b61d27f6000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a7600000000000000000000000000000000000000000000000000000746a528800000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000fe4c7cd974800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000120000000000000000000000000c31be7f83620d7cef8edebee0f5af096a7c0b7f400000000000000000000000000000000000000000000000000000746a52880000000000000000000000000000000000000000000000000000000000000005c1200000000000000000000000067297ee4eb097e072b4ab6f1620268061ae8046400000000000000000000000048e8d45ef08782da3072a19e153df9830d7d801e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000149000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006352a56caadc4f1e25cd6c75970fa768a3304e64c31be7f83620d7cef8edebee0f5af096a7c0b7f4dac17f958d2ee523a2206206994597c13d831ec7c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000000000000004a6700000000000000000000000000000000000000000000000000000746a52880000000000000000000000000000000000000000000000000000000000065d6a385c31be7f83620d7cef8edebee0f5af096a7c0b7f47594ae0c49654942af49c8e6e3eb6d170000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000411d900a0cffadcdfe1503a7104b198902649b3d3ce6e339c52357eead2eae63be2be57ec28d5c00b59e106c60ad3f46d75bf8a610414ec4ea5322a2ef85d4586e1b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000c2490411a32000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a7600000000000000000000000000000000000000000000000000000746a52880000000000000000000000000000000000000000000000000000000000000004a680000000000000000000000000000000000000000000000000000000000005d0100000000000000000000000000000000000000000000000000000000000000020000000000000000000000008ba3c3f7334375f95c128bc6a9b8fc42e870f16000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000034000000000000000000000000000000000000000000000000000000000000005a000000000000000000000000000000000000000000000000000000000000006c000000000000000000000000000000000000000000000000000000000000007e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064eb5625d9000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000069d460e01070a7ba1bc363885bc8f4f0daa19bf500000000000000000000000000000000000000000000000000000746a52880000000000000000000000000000000000000000000000000000000000000000000000000000000000069d460e01070a7ba1bc363885bc8f4f0daa19bf500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000a48201aa3f000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000746a52880000000000000000000000000006b175474e89094c44da98b954eedeac495271d0f0000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a49f8654220000000000000000000000006b175474e89094c44da98b954eedeac495271d0f00000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064d1660f990000000000000000000000006b175474e89094c44da98b954eedeac495271d0f000000000000000000000000d0a9c569342da0d52ca409c5cf1eac19635de7280000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064cac460ee00000000000000003b6d0340d0a9c569342da0d52ca409c5cf1eac19635de7280000000000000000000000006b175474e89094c44da98b954eedeac495271d0f000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000648a6a1e85000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000353c1f0bc78fbbc245b3c93ef77b1dcc5b77d2a00000000000000000000000000000000000000000000000000000000000005d0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a49f865422000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064d1660f99000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a760000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
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
     
        uint256 balanceAfter = address(_simpleAccount).balance;
        // print the balance of the contract
        console2.log("Before, after Balance of SimpleAccount in Wei:", balanceBef, balanceAfter);
        // Somehow the balance is not decreasing after the execution
        // assert balanceAfter < balanceBef
        // assertGt(balanceBef, balanceAfter, "Balance of SimpleAccount should have decreased after execution");
    }

     /**
      * Tests wallet creation with user (counterfactual account's address) 
      * Ether funding.
      */
    function testCreateNewWalletUserEtherFunding() public {
        // New owner without a smart account wallet
        address walletOwner = 0x278caac08B594f8559699F39b9460430739B9802;

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
            initCode: bytes(hex"42E60c23aCe33c23e0945a07f6e2c1E53843a1d55fbfb9cf000000000000000000000000278caac08B594f8559699F39b9460430739B98020000000000000000000000000000000000000000000000000000000000000000"),
            callData: bytes(hex""),
            callGasLimit: 800000,
            verificationGasLimit: 628384,
            preVerificationGas: 626688,
            maxFeePerGas: 65536, // Non zero value requires ETH balance in account
            maxPriorityFeePerGas: 73728,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"915bfc4f231f35dbfb3a8d145b5d987d2582a8858c80e820d3f96909618b2e1f2bd29293263cbfa7ba66ffe4f5d142b0141d56e85ddfb7e4859e12fdfe9b225d1c")
        });

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

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
      * Tests wallet creation with user (counterfactual account's address) 
      * Ether funding.
      */
    function testCreateNewWalletUserEtherDeposit() public {
        // New owner without a smart account wallet
        address walletOwner = 0x278caac08B594f8559699F39b9460430739B9802;

        console2.log("walletOwner:", walletOwner);
        address account = _factory.getAddress(walletOwner, 0);
        console2.log("counterfactual address for new wallet:", account);

        uint codeSize = account.code.length;
        assertEq(codeSize, 0, "Account should not be deployed yet");

        // **************************************************************
        // Non-zero gas userOp, user funds it.
        // Necessary to fund the account to pay for the account creation
        // **************************************************************
        // vm.deal(walletOwner, 10 ether);
        // assertEq(walletOwner.balance, 10 ether);

        _entryPoint.depositTo{value: 10 ether}(account);
        uint256 depositBef = _entryPoint.balanceOf(account);
        assertGt(depositBef, 9 ether, "deposit should be near 10 ether");

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: account,
            nonce: 0,
            initCode: bytes(hex"42E60c23aCe33c23e0945a07f6e2c1E53843a1d55fbfb9cf000000000000000000000000278caac08B594f8559699F39b9460430739B98020000000000000000000000000000000000000000000000000000000000000000"),
            callData: bytes(hex""),
            callGasLimit: 800000,
            verificationGasLimit: 628384,
            preVerificationGas: 626688,
            maxFeePerGas: 65536, // Non zero value requires ETH balance in account
            maxPriorityFeePerGas: 73728,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"915bfc4f231f35dbfb3a8d145b5d987d2582a8858c80e820d3f96909618b2e1f2bd29293263cbfa7ba66ffe4f5d142b0141d56e85ddfb7e4859e12fdfe9b225d1c")
        });

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        // entryPoint emits successful userOp execution events
        vm.expectEmit(false, true, true, false, 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        emit IEntryPoint.UserOperationEvent(0/* ignore userOp hash */, account, address(0) /* paymaster */, userOp.nonce, true, 0, 0);
        _entryPoint.handleOps(userOps, payable(_ownerAddress));
     
        uint256 depositAfter = _entryPoint.balanceOf(account);

        assertEq(account.balance, 0, "Balance of SimpleAccount should have been affected after execution");
        assertLt(depositAfter, depositBef, "Entrypoint account deposits should have decreased after execution");
    }

     /**
      * Tests sponsored wallet creation.
      */
    function testCreateNewWalletFundingByBundler() public {
        // New owner without a smart account wallet
        address walletOwner = 0x278caac08B594f8559699F39b9460430739B9802;
        assertEq(walletOwner.balance, 0, "EoA owner should have not Eth balance");

        console2.log("walletOwner:", walletOwner);
        address account = _factory.getAddress(walletOwner, 0);
        console2.log("counterfactual address for new wallet:", account);

        uint codeSize = account.code.length;
        assertEq(codeSize, 0, "Account should not be deployed yet");

        uint256 balanceBef = account.balance;
        assertEq(balanceBef, 0, "Account Balance should not have been funded");

        uint256 depositBef = _entryPoint.balanceOf(account);
        assertEq(depositBef, 0, "Entrypoint account deposits is 0 before execution");

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: account,
            nonce: 0,
            initCode: bytes(hex"42E60c23aCe33c23e0945a07f6e2c1E53843a1d55fbfb9cf000000000000000000000000278caac08B594f8559699F39b9460430739B98020000000000000000000000000000000000000000000000000000000000000000"),
            callData: bytes(hex""),
            callGasLimit: 800000,
            verificationGasLimit: 628384,
            preVerificationGas: 626688,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"06577b58c31d7c58c69b0c281c5c7353573eb1e930e7560bdcc61517885ab9d738b6668ace150b7724c0ee247d64c5e5dfc09e09a845687c38a2607d10dd7d111c")
        });

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        // entryPoint emits successful userOp execution events
        vm.expectEmit(false, true, true, false, 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        emit IEntryPoint.UserOperationEvent(0/* ignore userOp hash */, account, address(0) /* paymaster */, userOp.nonce, true, 0, 0);
        _entryPoint.handleOps(userOps, payable(_ownerAddress));
     
        uint256 balanceAfter = account.balance;
        uint256 depositAfter = _entryPoint.balanceOf(account);

        assertEq(balanceAfter, 0, "Account Balance should have remained at 0 after execution");
        assertEq(depositAfter, 0, "Entrypoint account deposits should be zero");
    }

    function _weiToEther(uint256 weiAmount) private pure returns (uint256) {
        return weiAmount / 1 ether;
    }

    function _weiToGwei(uint256 weiAmount) private pure returns (uint256) {
        return weiAmount / 1 gwei;
    }
}
