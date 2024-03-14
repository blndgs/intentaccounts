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
        assertEq(_ownerAddress, 0x230E2313F1de75875D9bE9cd7fD670b2dFa1c117, "Owner address should match");
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
        _factory = SimpleAccountFactory(0x2564193458ffe133fEc5Ca8141E0181CaD1B458d);
        console2.log("SimpleAccountFactory synced at:", address(_factory));
        uint256 endGas = gasleft();
        console2.log("Gas used for Factory sync: ", startGas - endGas);
        startGas = endGas;

        // Use the _factory to create a new SimpleAccount instance
        // _simpleAccount = _factory.createAccount(_ownerAddress, _salt);
        // assertEq(address(_simpleAccount), 0x132553833bD6832e0C283C5b27EDf90B256926EC);
        // console2.log("SimpleAccount wallet created at:", address(_simpleAccount));
        // console2.log("Gas used for wallet creation: ", startGas - endGas);
        // startGas = endGas;
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
            hex"d6f6b170000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000038d7ea4c680000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a76000000000000000000000000ae7ab96520de3a18e5e111b5eaab095312d7fe840000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000015000000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a76000000000000000000000000000000000000000000000000000009184e72a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013e4ac9650d8000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000132000000000000000000000000000000000000000000000000000000000000012a4c7cd974800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000120000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a76000000000000000000000000000000000000000000000000000009184e72a00000000000000000000000000000000000000000000000008bb4bddded42f0a66a00000000000000000000000067297ee4eb097e072b4ab6f1620268061ae8046400000000000000000000000048e8d45ef08782da3072a19e153df9830d7d801e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000149000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001111111254eeb25477b68fb85ed929f73a960582a092801fc37902ffa1b93f12b61ce32609208e2bc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000070e4cd251cd13bbce0000000000000000000000000000000000000000000000000000009184e72a0000000000000000000000000000000000000000000000000000000000065e9f0dfa092801fc37902ffa1b93f12b61ce32609208e2bf0b8591a3998478b8277bda05959ad70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041439a432e6401940a42015991d0f2cd9efc7ec9e82b65203325a191080304fc0f525e673680aefbd05d8e668f56262c625bd31854cb17aeee6be3295cf497b0701c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000ee812aa3caf000000000000000000000000e37e799d5077682fa0a244d46e5649f71457bd09000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000e37e799d5077682fa0a244d46e5649f71457bd09000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a76000000000000000000000000000000000000000000000000000009184e72a000000000000000000000000000000000000000000000000070e4cd251cd13e95fe00000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d56000000000000000000000000000000000000000d38000d0a000cc0000ca600a0c9e75c4800000000000000000703000000000000000000000000000000000000000000000000000c7800052f00a0c9e75c48000000100a09040404030000000000000000000005010003080002b900026a00021b0001a00000d05100f5f5b97624542d72a9e06f04804bf81baa15e2b4dac17f958d2ee523a2206206994597c13d831ec70044394747c5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002084e2c757bd5d8dd00000000000000000000000000000000000000000000000000000000000000005100d51a44d3fae010294c616388b506acda1bfaae46dac17f958d2ee523a2206206994597c13d831ec70044394747c5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b73018290e1cdafc00000000000000000000000000000000000000000000000000000000000000000c20dac17f958d2ee523a2206206994597c13d831ec70d4a11d5eeaac28ec3f61d100daf4d40471f18526ae4071118002dc6c00d4a11d5eeaac28ec3f61d100daf4d40471f1852000000000000000000000000000000000000000000000002b3e057bfcb92ef83dac17f958d2ee523a2206206994597c13d831ec702a0000000000000000000000000000000000000000000000002b5a7d0aaa50a80abee63c1e5006ca298d2983ab03aa1da7679389d955a4efee15cdac17f958d2ee523a2206206994597c13d831ec702a000000000000000000000000000000000000000000000000613c3cdf4d28b1fccee63c1e5004e68ccd3e89f51c3074ca5072bbac773960dfa36dac17f958d2ee523a2206206994597c13d831ec702a0000000000000000000000000000000000000000000000006c52b0de673326d42ee63c1e50011b815efb8f581194ae79006d24e0d814b7697f6dac17f958d2ee523a2206206994597c13d831ec700a0860a32ec000000000000000000000000000000000000000000000000000000d4eff336650001d051201111111254eeb25477b68fb85ed929f73a960582dac17f958d2ee523a2206206994597c13d831ec701043eca9c0a000000000000000000000000000000000000000065e9f066a74345b18a3b0b18000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000807cf9a772d5a3f9cefbc1192e939d62f0d9bd38000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cf2661b19fdeb90a0000000000000000000000000000000000000000000000000000000d4eff33665000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041e1831a44fd7ca8bb0d63844326e464f7c508e12bde8689d6e0fa153ef9392b7144aeb81836bb9a99ddadc94b57a980709aa2d430b69b30149a8a239567d99bd51b0000000000000000000000000000000000000000000000000000000000000000a007e5c0d200000000000000000000000000000000000000000000000000072500016b00a0c9e75c480000000000000000230f00000000000000000000000000000000000000000000000000013d0000ee00a007e5c0d20000000000000000000000000000000000000000000000000000ca0000b05100bebc44782c7db0a1a60cb6fe97d0b483032ff1c7dac17f958d2ee523a2206206994597c13d831ec700443df02124000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001876c1f43a00020d6bdbf78a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4802a000000000000000000000000000000000000000000000000000000391542b9928ee63c1e5003416cf6c708da44db2624d63ea0aaef7113527c6dac17f958d2ee523a2206206994597c13d831ec700a0c9e75c480000000026030201ff0600000000000000000000000000058c00053d0003440002f500027a00026000a007e5c0d200000000000000000000000000000000023c0002360001860000ca0000b05120a5407eae9ba41422680e2e00537571bcc53efbfda0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800443df0212400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010020d6bdbf7857ab1ec28d129707052df4df418d58a2d46d5f514120c011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f002444b3e92373555344000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000734554480000000000000000000000000000000000000000000000000000000031494e434800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005120c5424b857f758e906013f3555dad202e4bdb45675e74c9036fb86bd7ecdcb084a0673efc32ea31cb00443df02124000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100206b4be0b94041c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2d0e30db00c20a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48b4e16d0168e52d35cacd2c6185b44281ec28c9dc6ae4071198002dc6c0b4e16d0168e52d35cacd2c6185b44281ec28c9dc00000000000000000000000000000000000000000000000193a074214e0928f1a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4802a000000000000000000000000000000000000000000000000327f0b24e38ea8c6cee63c1e5018ad599c3a0ff1de082011efddc58f1908eb6e6d8a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800a0860a32ec00000000000000000000000000000000000000000000000000000061db38d08f0001d051001111111254eeb25477b68fb85ed929f73a960582a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4801043eca9c0a000000000000000000000000000000000000000065e9f066add51865a76cb798000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000807cf9a772d5a3f9cefbc1192e939d62f0d9bd380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005f16bdd247fd3c1fe00000000000000000000000000000000000000000000000000000061db38d08f0000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000418c02584ecd590194227917f9419cea1825d1043440561e2a0f7b17ab2d7af36a109a01742a6b6d79bb33ac5da6862dfa1fb145316f33642550cc77b63a95dace1c0000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000003c11fcd3f89ce3c1c9ee63c1e50188e6a0c2ddd26feeb64f039a2c41296fcb3f5640a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480020d6bdbf78c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200a0f2fa6b66c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000008d1e006e64058e3b7e00000000000000000004a224cd11f3a380a06c4eca27c02aaa39b223fe8d0a0e5c4f27ead9083c756cc21111111254eeb25477b68fb85ed929f73a96058200000000000000000000d3a129fa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004449404b7c00000000000000000000000000000000000000000000008bb4bddded42f0a66a000000000000000000000000a092801fc37902ffa1b93f12b61ce32609208e2b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024a1903eab000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
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

    function logBytes32Value(string memory prompt, bytes32 value) public pure {
        // Convert bytes32 to string
        string memory valueAsString = toHexString(abi.encodePacked(value));

        // Log the value
        console2.log(prompt, valueAsString);
    }

    function toHexString(bytes memory b) internal pure returns (string memory) {
        bytes memory hexString = new bytes(2 * b.length + 2);
        hexString[0] = "0";
        hexString[1] = "x";

        for (uint256 i = 0; i < b.length; i++) {
            uint256 value = uint8(b[i]);
            uint256 hi = value / 16;
            uint256 lo = value - (hi * 16);

            bytes1 hiHexChar = bytes1(uint8(hi < 10 ? hi + 48 : hi + 87));
            bytes1 loHexChar = bytes1(uint8(lo < 10 ? lo + 48 : lo + 87));

            hexString[2 * i + 2] = hiHexChar;
            hexString[2 * i + 3] = loHexChar;
        }

        return string(hexString);
    }
}
