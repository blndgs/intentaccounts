// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@account-abstraction/utils/Exec.sol";
import "../src/IntentSimpleAccount.sol";
import "@account-abstraction/interfaces/IEntryPoint.sol";
import "@account-abstraction/core/EntryPoint.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/IntentSimpleAccountFactory.sol";
import "./TestSimpleAccountHelper.sol";

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

interface ISquidMulticall {
    enum CallType { Default, FullTokenBalance, FullNativeBalance, CollectTokenBalance }
    
    struct Call {
        CallType callType;
        address target;
        uint256 value;
        bytes callData;
        bytes payload;
    }

    function run(Call[] calldata calls) external payable;
}

contract callsTest is Test {
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    ContractB b;
    address public _ownerAddress;
    uint256 public _ownerPrivateKey;

    using ECDSA for bytes32;

    IntentSimpleAccount _simpleAccount;
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
        console2.log("Owner address:", _ownerAddress);

        vm.createSelectFork(vm.envString("ETHEREUM_RPC_URL"));

        // Deploy the EntryPoint contract or use an existing one
        _entryPoint = EntryPoint(payable(ENTRYPOINT_V06));
        console2.log("EntryPoint deployed at:", address(_entryPoint));

        // Deploy ContractB
        b = new ContractB();

        // Create a 4337 wallet
        IntentSimpleAccountFactory factory = new IntentSimpleAccountFactory(_entryPoint);
        _simpleAccount = factory.createAccount(_ownerAddress, salt);
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
    
    function testSquidMultiCallGetDAIBalance() public {
        address SQUID_MULTICALL = 0xEa749Fd6bA492dbc14c24FE8A3d08769229b896c;
        address DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
        address WALLET = 0xc291efDc1a6420CBB226294806604833982Ed24d;
        
        // fund/faucet wallet with DAI balance
        deal(DAI, address(_simpleAccount), 1000e18); // 1000 DAI;
    
        // Create the multicall data
        ISquidMulticall.Call[] memory calls = new ISquidMulticall.Call[](1);
        calls[0] = ISquidMulticall.Call({
            callType: ISquidMulticall.CallType.Default,
            target: DAI,
            value: 0,
            callData: abi.encodeWithSignature("balanceOf(address)", WALLET),
            payload: ""
        });
    
        // Encode the multicall data
        bytes memory squidMulticallCalldata = abi.encodeWithSignature("run((uint8,address,uint256,bytes,bytes)[])", calls);
    
        // Execute the call
        (bool success, bytes memory returnData) = SQUID_MULTICALL.call(squidMulticallCalldata);
    
        // Log the success status
        console.log("Multicall success:", success);
    
        // Log the length of return data
        console.log("Return data length:", returnData.length);
    
        if (!success) {
            // If the call failed, try to decode the revert reason
            if (returnData.length > 4) {
                bytes memory reasonSlice = TestSimpleAccountHelper._slice(returnData, 4, returnData.length);
                (string memory reason) = abi.decode(reasonSlice, (string));
                console.log("Revert reason:", reason);
            } else {
                console.log("Call reverted without a reason");
            }
            revert("Multicall failed");
        }
    
        // If no data was returned, try calling the DAI contract directly
        if (returnData.length == 0) {
            console.log("No data returned from multicall, trying direct call");
            (success, returnData) = DAI.staticcall(abi.encodeWithSignature("balanceOf(address)", WALLET));
            require(success, "Direct DAI call failed");
            uint256 balance = abi.decode(returnData, (uint256));
            console.log("DAI Balance (direct call):", balance);
            assertNotEq(balance, 0, "DAI balance is zero");
        } else {
            // The return data is an array of results, one for each call
            (bytes[] memory results) = abi.decode(returnData, (bytes[]));
    
            // Log the number of results
            console.log("Number of results:", results.length);
    
            // We only made one call, so we're interested in the first (and only) result
            if (results.length > 0) {
                uint256 balance = abi.decode(results[0], (uint256));
                console.log("DAI Balance:", balance);
                // Assert that the balance is what we expect
                assertEq(balance, 998000000000000000000, "Unexpected DAI balance");
            } else {
                revert("No results returned from multicall");
            }
        }
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

    /**
     * @dev This function takes a fixed calldata template and replaces a specific address within it.
     *      The template represents a call to SimpleAccount's execute function, which in turn calls the ERC20 approve function.
     * @param smtAddress `(Super Mario Token)` or the address of the ERC20 token contract to be approved
     * @return bytes The modified calldata with the correct token address
     *
     * @custom:structure The fixed calldata structure is as follows:
     *   - bytes4  : Function selector for SimpleAccount's execute function (0xb61d27f6)
     *   - address : Token address (to be replaced)
     *   - uint256 : ETH Value (0 in this case)
     *   - bytes   : Encoded call to approve function
     *     - bytes4  : Function selector for ERC20's approve function (0x095ea7b3)
     *     - address : Spender address
     *     - uint256 : Amount to approve
     *
     * @custom:example
     * Input:
     *   smtAddress: 0x1234567890123456789012345678901234567890
     *
     * Output (hexadecimal):
     *   b61d27f6
     *   000000000000000000000000{smtAddress}
     *   0000000000000000000000000000000000000000000000000000000000000000
     *   0000000000000000000000000000000000000000000000000000000000000060
     *   0000000000000000000000000000000000000000000000000000000000000044
     *   095ea7b3
     *   000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a76
     *   0000000000000000000000000000000000000000000000000000000000000378
     *   00000000000000000000000000000000000000000000000000000000
     */
    function generateCallData(address smtAddress) internal pure returns (bytes memory) {
        bytes memory fixedCallData =
            hex"b61d27f60000000000000000000000002e234dae75c793f67a35089c9d99245e1c58470b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a76000000000000000000000000000000000000000000000000000000000000037800000000000000000000000000000000000000000000000000000000";

        // Convert the Smt address to bytes
        bytes memory smtAddressBytes = abi.encodePacked(smtAddress);

        // Replace the incorrect address with the Smt address
        for (uint256 i = 0; i < 20; i++) {
            fixedCallData[i + 16] = smtAddressBytes[i];
        }

        return fixedCallData;
    }

    function test4337Approve() public {
        console2.log("sender:", address(_simpleAccount));

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: address(_simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                "{\"from\":{\"type\":\"TOKEN\",\"address\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"amount\":\"0.8\",\"chainId\":\"1\"},\"to\":{\"type\":\"TOKEN\",\"address\":\"0xdac17f958d2ee523a2206206994597c13d831ec7\",\"chainId\":\"1\"}}"
            ),
            callGasLimit: 800000,
            verificationGasLimit: 100000,
            preVerificationGas: 10000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = _simpleAccount.getNonce();
        console2.log("nonce:", userOp.nonce);

        // 2. SDK signs the intent userOp
        console2.log("chain ID:", block.chainid);
        userOp.signature = generateSignature(userOp, block.chainid);
        console2.log("signature:");
        console2.logBytes(userOp.signature);

        // 3. SDK submits to Bundler...
        // 4. Bundler submits userOp to the Solver

        // 5. Solver solves Intent userOp
        userOp.signature = bytes(abi.encodePacked(userOp.signature, userOp.callData));
        userOp.callData = generateCallData(address(smt));

        console2.log("intent signature:");
        console2.logBytes(userOp.signature);

        // 6. Bundler submits solved userOp on-chain

        verifySignature(userOp);
        console2.log("userOp signature verified");

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        // entryPoint emits events
        vm.expectEmit(false, true, true, false, 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        emit IEntryPoint.UserOperationEvent(
            0, /* ignore userOp hash */ address(_simpleAccount), address(0), /* paymaster */ userOp.nonce, true, 0, 0
        );
        // 7. entryPoint executes the intent userOp
        _entryPoint.handleOps(userOps, payable(_ownerAddress));

        uint256 allowance = smt.allowance(address(_simpleAccount), spender);
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
        uint256 result = _simpleAccount.validateSignature(userOp, bytes32(0));
        assertEq(result, 0, "Signature is not valid for the userOp");

        return result;
    }
}
