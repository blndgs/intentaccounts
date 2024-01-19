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
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _call(dest, value, func);
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

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
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

        // Deploy the EntryPoint contract or use an existing one
        // entryPoint = EntryPoint(payable(ENTRYPOINT_V06));
        entryPoint = new EntryPoint();
        ENTRYPOINT_V06 = address(entryPoint);

        // Deploy the SimpleAccountFactory with the entry point
        factory = new SimpleAccountFactory(entryPoint);

        // Create an account using the factory
        simpleAccount = factory.createAccount(ownerAddress, salt);
        console2.log("SimpleAccount deployed at:", address(simpleAccount));

        // Create an SMT token
        smt = new Smt();

        uint256 amount = 100 ether;

        // Fund the ownerAddress with the specified amount of Ether
        vm.deal(ownerAddress, amount);
        vm.deal(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789, amount);
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
}
