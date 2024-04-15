// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Exec.sol";
import "../src/SimpleAccount.sol";
import "../src/IEntryPoint.sol";
import "../src/EntryPoint.sol";
import "../src/SimpleAccountFactory.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "../src/ECDSA.sol";

using Strings for bytes32;
using UserOperationLib for UserOperation;

contract Smt is ERC20 {
    constructor() ERC20("Super Morpheus Tokens", "SMT") {
        this;
        mint(msg.sender, 10 ** 27);
    }

    function mint(address to, uint256 amount) public virtual {
        _mint(to, amount);
    }

    function burn(address form, uint256 amount) public virtual {
        _burn(form, amount);
    }
}

contract ContractB {
    using Strings for address;

    mapping(address => uint256) public balances;
    string valueRet = "myValue";

    function foo(address target) external {
        _call(
            target,
            0,
            bytes(
                hex"095ea7b3000000000000000000000000d7b21a844f3a41c91a73d3f87b83fa93bb6cb5180000000000000000000000000000000000000000000000000000000000000378"
            )
        );
    }

    /**
     * execute a transaction just like entrypoint would call in a 4337 wallet
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _call(dest, value, func);
    }

    /**
     * @dev Executes a delegate call in the caller's function storage context.
     * @param to The address of the contract to delegate call to.
     * @param data The calldata to send with the delegate call.
     * @param txGas The amount of gas to allocate for the delegate call.
     * @return success A boolean indicating whether the call was successful.
     * Delegate calls execute the code of the target address in the context of the calling contract.
     */
    function delegateCall(address to, bytes memory data, uint256 txGas) external returns (bool success) {
        return Exec.delegateCall(to, data, txGas);
    }

    /**
     * @dev Performs a call and reverts the transaction if the call is unsuccessful.
     * @param to The address to call.
     * @param data The calldata to send.
     * @param maxLen The maximum length of the revert data to handle.
     * This function is a convenience method that combines a call and conditional revert.
     */
    function callAndRevert(address to, bytes memory data, uint256 maxLen) external {
        return Exec.callAndRevert(to, data, maxLen);
    }

    /**
     * @dev Executes a regular contract call in the called's function storage context.
     * @param to The address of the contract to call.
     * @param value The amount of Ether to send with the call.
     * @param data The calldata to send with the call.
     * @param txGas The amount of gas to allocate for the call.
     * @return success A boolean indicating whether the call was successful.
     * Inline assembly is used to optimize gas consumption and direct control over the EVM.
     */
    function call(address to, uint256 value, bytes memory data, uint256 txGas) external returns (bool success) {
        return Exec.call(to, value, data, txGas);
    }

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func) external {
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    function _call(address target, uint256 value, bytes memory data) public {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}

contract callsTest is Test {
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 mumbaiFork;
    ContractB b;
    address public _ownerAddress;
    uint256 public _ownerPrivateKey;

    using ECDSA for bytes32;

    SimpleAccountFactory public factory;
    SimpleAccount _simpleAccount;
    uint256 salt = 0;
    IEntryPoint public entryPoint;
    Smt smt;
    string _network;
    IEntryPoint _entryPoint;
    address spender = 0xEAd050515E10fDB3540ccD6f8236C46790508A76;

    function setUp() public {
        string memory privateKeyEnv = string(abi.encodePacked(_network, "ETHEREUM_PRIVATE_KEY"));
        string memory privateKeyString = vm.envString(privateKeyEnv);

        // Derive the Ethereum address from the private key
        _ownerPrivateKey = vm.parseUint(privateKeyString);
        _ownerAddress = vm.addr(_ownerPrivateKey);
        assertEq(_ownerAddress, 0xc9164f44661d83d01CbB69C0b0E471280f446099, "Owner address should match");

        mumbaiFork = vm.createSelectFork(vm.envString("ETHEREUM_RPC_URL"));
        // vm.startPrank(_ownerAddress);

        // Deploy the EntryPoint contract or use an existing one
        _entryPoint = EntryPoint(payable(ENTRYPOINT_V06));
        console2.log("EntryPoint deployed at:", address(_entryPoint));

        // Deploy ContractB
        b = new ContractB();

        // Sync with deployed Eth mainnet 4337 wallet
        _simpleAccount = SimpleAccount(payable(0xc31bE7F83620D7cEF8EdEbEe0f5aF096A7C0b7F4));
        console2.log("_SimpleAccount deployed at:", address(_simpleAccount));

        // Create an SMT token
        smt = new Smt();
        console2.log("SMT deployed at:", address(smt));

        // fund owner
        vm.deal(_ownerAddress, 100 ether);

        console2.log("msg.sender: ", msg.sender);
        console2.log("address(this): ", address(this));
        console2.log("address(b)", address(b));
    }

    // Contract calls illustrasted in multiple ways
    function testCallDo() external payable {
        // Use the address of the deployed ContractB instance
        address target = address(b);

        address erc20token = address(smt);

        // Prepare call data for 'foo()' function
        bytes memory callData = abi.encodeWithSignature("foo(address)", erc20token);

        // Call 'foo()' function in ContractB using a low-level call
        // Custom call to 'foo()' function in ContractB
        bool success = Exec.call(target, 0, callData, gasleft());

        // Check if the call was successful
        require(success, "Call to ContractB failed");

        // Call execute() function in ContractB using a Yul call
        // through indirection via execute(), which calls _call()
        address to = address(smt);
        b.execute(
            to,
            0,
            bytes(
                hex"095ea7b3000000000000000000000000d7b21a844f3a41c91a73d3f87b83fa93bb6cb5180000000000000000000000000000000000000000000000000000000000000378"
            )
        );

        bytes memory data = bytes(
            hex"095ea7b3000000000000000000000000d7b21a844f3a41c91a73d3f87b83fa93bb6cb5180000000000000000000000000000000000000000000000000000000000000378"
        );
        (success,) = to.call(data);
        require(success, "Call to ContractB failed");

        // Yul call() example
        uint256 value = 0;

        assembly {
            let dataLength := mload(data) // Load the length of data from the first 32 bytes

            // add(data, 32) adjusts the pointer to skip the length prefix of the
            // dynamic array, and dataLength is the actual length of the data.
            success := call(300000, to, value, add(data, 32), dataLength, 0, 0)
        }
        require(success, "Yul call failed");
    }

    function testApprove() external payable {
        uint256 amount = 8000; // equivalent to 0.008 * 10 ** 6 in USDC decimals

        // 1st call
        console.log("smt.approve(spender, amount)");
        smt.approve(spender, amount);

        address erc20token = address(smt);
        bytes memory data = abi.encodeWithSelector(IERC20.approve.selector, spender, amount);

        // 2nd call
        console2.log("Exec.delegateCall(erc20token, data, gasleft())");
        bool success = Exec.delegateCall(erc20token, data, gasleft());
        require(success, "Delegate call failed");

        // 3rd call
        console2.log("Exec.callAndRevert(erc20token, data, 512)");
        Exec.callAndRevert(erc20token, data, 512);
        require(success, "Call and revert failed");

        // Use the address of the deployed ContractB instance
        address btarget = address(b);
        bytes memory dataB = bytes(
            hex"369e7c410000000000000000000000005991a2df15a8f6a256d3ec51e99254cd3fb576a9000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000493e00000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a76000000000000000000000000000000000000000000000000000000000000037800000000000000000000000000000000000000000000000000000000"
        );
        console2.log("Exec.Call->b.delegateCall->erc20token.approve(spender, amount)");
        success = Exec.call(btarget, 0, dataB, gasleft());

        dataB = bytes(
            hex"f2addfd70000000000000000000000005991a2df15a8f6a256d3ec51e99254cd3fb576a9000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a76000000000000000000000000000000000000000000000000000000000000037800000000000000000000000000000000000000000000000000000000"
        );
        console2.log("Exec.call->b.callAndRevert->erc20token.approve(spender, amount)");
        success = Exec.call(btarget, 0, dataB, gasleft());

        // Check if the call was successful
        require(success, "Call using Exec.call failed");

        // Call execute() function in ContractB using a Yul call
        // through indirection via execute(), which calls _call()
        console2.log("b.execute(erc20token, 0, data)");
        b.execute(erc20token, 0, data);

        console2.log("erc20Token.call(data)");
        (success,) = erc20token.call(data);
        require(success, "Call to ContractB failed");

        // Yul call() example
        uint256 value = 0;

        console2.log("Yul call(300000, erc20token, value, add(data, 32), dataLength, 0, 0)");
        assembly {
            let dataLength := mload(data) // Load the length of data from the first 32 bytes

            // add(data, 32) adjusts the pointer to skip the length prefix of the
            // dynamic array, and dataLength is the actual length of the data.
            success := call(300000, erc20token, value, add(data, 32), dataLength, 0, 0)
        }
        require(success, "Yul call failed");
    }

    function test4337Approve() public {
        console2.log("sender:", address(_simpleAccount));

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
            hex"b61d27f60000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a76000000000000000000000000000000000000000000000000000000000000037800000000000000000000000000000000000000000000000000000000"
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

        uint allowance = smt.allowance(address(_simpleAccount), spender);
        assertEq(allowance, 888, "Allowance should be 888 for simpleAccount");
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
}
