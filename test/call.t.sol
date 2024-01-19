pragma solidity ^0.8.0;

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
        mint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789, 10 ** 27);
        // dynamic entrypoint
        mint(0xbc1CBee1dD2c8a235DC75D9dE77EB049aa930cAB, 10 ** 27);
        console2.log("Supply:", totalSupply());
        console2.log("SMT owner:", msg.sender);
        console2.log("balance of owner:", balanceOf(msg.sender));
    }

    function mint(address to, uint256 amount) public virtual {
        _mint(to, amount);
    }

    function burn(address form, uint256 amount) public virtual {
        _burn(form, amount);
    }
}

contract ContractB {
    mapping(address => uint256) public balances;
    string valueRet = "myValue";

    function foo() external {
        console2.log("foo() msg.sender:", msg.sender);
        console2.log("msg.sender balance:", address(msg.sender).balance);
        _call(
            0xA48aa11C63Fb430b8a321aE5a7e13A9F4Ae99024,
            0,
            bytes(hex"095ea7b3000000000000000000000000d7b21a844f3a41c91a73d3f87b83fa93bb6cb5180000000000000000000000000000000000000000000000000000000000000378")
        );
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        console2.log("entered execute()", dest);
        console2.log("msg.sender", msg.sender);
        console2.log("value", value);
        console2.log("func", string(func));
        _call(dest, value, func);
    }

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func) external {
        console2.log("entered executeBatch()");
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        console2.log("entered _call");
        console2.log("target", target);
        console2.log("value", value);
        console2.logBytes(data);
        (bool success, bytes memory result) = target.call{value: value}(data);
        console2.log("success", success);
        console2.log("result", string(result));
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}

contract aTest is Test {
    address ENTRYPOINT_V06;
    // address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 mumbaiFork;
    ContractB b;
    address public ownerAddress;
    uint256 public ownerPrivateKey;

    using ECDSA for bytes32;

    SimpleAccountFactory public factory;
    SimpleAccount simpleAccount;
    uint256 salt = 0;
    IEntryPoint public entryPoint;
    Smt smt;

    function setUp() public {
        string memory mumbaiPrivateKeyString = vm.envString("MUMBAI_PRIVATE_KEY");

        // Derive the Ethereum address from the private key
        ownerPrivateKey = vm.parseUint(mumbaiPrivateKeyString);
        ownerAddress = vm.addr(ownerPrivateKey);
        assertEq(ownerAddress, 0xa4BFe126D3aD137F972695dDdb1780a29065e556, "Owner address should match");

        mumbaiFork = vm.createSelectFork(vm.envString("MUMBAI_RPC_URL"));
        vm.startPrank(ownerAddress);

        // Deploy ContractB
        b = new ContractB();

        entryPoint = new EntryPoint();
        ENTRYPOINT_V06 = address(entryPoint);

        // Deploy the EntryPoint contract or use an existing one
        // entryPoint = EntryPoint(payable(ENTRYPOINT_V06));
        console2.log("EntryPoint deployed at:", address(entryPoint));

        // Deploy the SimpleAccountFactory with the entry point
        factory = new SimpleAccountFactory(entryPoint);

        // Create an account using the factory
        simpleAccount = factory.createAccount(ownerAddress, salt);
        console2.log("SimpleAccount deployed at:", address(simpleAccount));

        // Create an SMT token
        smt = new Smt();
        console2.log("SMT deployed at:", address(smt));

        uint256 amount = 100 ether; // Amount of Ether you want to allocate

        // Check the new balance (optional, for verification)
        uint256 origBalance = address(ownerAddress).balance;
        console.log("Original Ether balance of ownerAddress:", origBalance);

        // Fund the ownerAddress with the specified amount of Ether
        vm.deal(ownerAddress, amount);
        vm.deal(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789, amount);

        // Check the new balance (optional, for verification)
        uint256 newBalance = address(ownerAddress).balance;
        console.log("New Ether balance of ownerAddress:", newBalance);
    }

    // Function to call 'foo' in ContractB
    function testCallDo() external payable {
        // Use the address of the deployed ContractB instance
        address target = address(b);

        // Prepare call data for 'foo()' function
        bytes memory callData = abi.encodeWithSignature("foo()");

        // Call 'foo()' function in ContractB using a low-level call
        // Custom call to 'foo()' function in ContractB
        bool success = Exec.call(target, 0, callData, gasleft());

        // Check if the call was successful
        require(success, "Call to ContractB failed");

        // b.execute(
        //     0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789,
        //     35000,
        //     bytes(
        //         hex"b760faf9000000000000000000000000a4bfe126d3ad137f972695dddb1780a29065e556"
        //     )
        // );
        // simpleAccount.execute(target, 0, bytes(hex""));
        // simpleAccount.execute(target, 0, bytes(hex'095ea7b3000000000000000000000000d7b21a844f3a41c91a73d3f87b83fa93bb6cb5180000000000000000000000000000000000000000000000000000000000000378'));
        address to = address(smt);
        bytes memory data = bytes(hex"095ea7b3000000000000000000000000d7b21a844f3a41c91a73d3f87b83fa93bb6cb5180000000000000000000000000000000000000000000000000000000000000378");
        uint256 value = 35000;
        (success, ) = to.call{value: value}(data);
        console2.log("success2", success);

        // Send Ether using low-level call
        assembly {
            success := call(300000, to, value, data, mload(data), 0, 0)
        }
        console2.log("success3", success);
    }
}
