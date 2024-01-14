// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

import "./BaseAccount.sol";
import "./TokenCallbackHandler.sol";

/**
 * minimal account.
 *  this is sample minimal account.
 *  has execute, eth handling methods
 *  has a single signer that can send requests through the entryPoint.
 */
contract SimpleAccount is BaseAccount, TokenCallbackHandler, UUPSUpgradeable, Initializable {
    using UserOperationLib for UserOperation;

    bytes private constant INTENT_END = hex"3c696e74656e742d656e643e"; // "<intent-end>"
    bytes private constant INTENT_END_LEN = 12; // "<intent-end>"

    // Custom errors
    error EndLessThanStart();
    error EndOutOfBounds(uint256 dataLength, uint256 end);
    error StartOutOfBounds(uint256 dataLength, uint256 start);

    using ECDSA for bytes32;

    address public owner;

    IEntryPoint private immutable _entryPoint;

    event SimpleAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    function _onlyOwner() internal view {
        //directly from EOA owner, or through the account itself (which gets redirected through execute())
        require(msg.sender == owner || msg.sender == address(this), "only owner");
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of SimpleAccount must be deployed with the new EntryPoint address, then upgrading
     * the implementation by calling `upgradeTo()`
     */
    function initialize(address anOwner) public virtual initializer {
        _initialize(anOwner);
    }

    function _initialize(address anOwner) internal virtual {
        owner = anOwner;
        emit SimpleAccountInitialized(_entryPoint, owner);
    }

    // Require the function call went through EntryPoint or owner
    function _requireFromEntryPointOrOwner() internal view {
        require(msg.sender == address(entryPoint()) || msg.sender == owner, "account: not Owner or EntryPoint");
    }

    uint256 private constant SKIP_WRAPPER_CD_BYTES = 132; // 128 + 4 (unknown why 4, maybe the abi-encoded length of the Intent JSON)

    /**
     * @dev Expose _getUserOpHash for testing
     */
    function getUserOpHash(UserOperation calldata userOp, uint256 chainID) external view returns (bytes32) {
        return _getUserOpHash(userOp, chainID);
    }

    function _getUserOpHash(UserOperation calldata userOp, uint256 chainID) internal view returns (bytes32) {
        bytes memory callData = userOp.callData;

        // Check if calldata contains an Intent JSON followed by <intent-end>
        int256 endIndex = _findIntentEndIndex(callData, true);

        if (endIndex != -1) {
            // Intent JSON exists, so include only the part before <intent-end> for hashing
            callData = _slice(callData, SKIP_WRAPPER_CD_BYTES, uint256(endIndex));
        }

        return keccak256(abi.encode(userOp.hashIntentOp(callData), address(_entryPoint), chainID));
    }

    /**
     * @dev Expose _findIntentEndIndex for testing
     */
    function findIntentEndIndex(bytes memory data, bool skip) external pure returns (int256) {
        return _findIntentEndIndex(data, skip);
    }

    // Helper function to find the index of <intent-end> token in hex in the calldata
    // after skipping the first 128 bytes of the calldata which is the wrapper Entrypoint
    // calldata which is the abi-encoded execute() function call and arguments.
    // At position 128, the calldata contains the abi-encoded UserOperation calldata.
    // Search logic to return the index of <intent-end> or -1 if not found
    function _findIntentEndIndex(bytes memory data, bool skip) internal pure returns (int256) {
        // Conditionally skip the first SKIP_WRAPPER_CD_BYTES bytes if indicated and if the data length allows it
        uint256 adjustedStartIndex = (skip && data.length > SKIP_WRAPPER_CD_BYTES) ? SKIP_WRAPPER_CD_BYTES : 0;

        if (data.length < adjustedStartIndex + INTENT_END_LEN) {
            return -1;
        }

        // Start the search loop from the adjusted index
        for (uint256 i = adjustedStartIndex; i <= data.length - INTENT_END_LEN; i++) {
            bool matchToken = true;
            for (uint256 j = 0; j < INTENT_END_LEN; j++) {
                if (data[i + j] != INTENT_END[j]) {
                    matchToken = false;
                    break;
                }
            }
            if (matchToken) {
                return int256(i);
            }
        }

        return -1; // Not found
    }

    // Helper function to slice the bytes array (Intent in calldata) up to a certain length (start of token)
    // Slicing logic in Solidity to return the part of the data from start to end
    function _sliceSol(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory) {
        if (end <= start) revert EndLessThanStart();
        if (end > data.length) revert EndOutOfBounds(data.length, end);
        if (start >= data.length) revert StartOutOfBounds(data.length, start);

        bytes memory result = new bytes(end - start);
        for (uint256 i = start; i < end; i++) {
            result[i - start] = data[i];
        }
        return result;
    }

    /**
     * @dev Expose _slice for testing
     */
    function slice(bytes memory data, uint256 start, uint256 end) external pure returns (bytes memory result) {
        return _slice(data, start, end);
    }

    // Helper function to slice the bytes array (Intent in calldata) up to a certain length (start of token)
    // Slicing logic in Yul to return the part of the data from start to end
    function _slice(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory result) {
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

    /// implement template method of BaseAccount
    function _validateSignature(UserOperation calldata userOp, bytes32)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        bytes32 userOpHash = _getUserOpHash(userOp, block.chainid);
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        if (owner != hash.recover(userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlyOwner();
    }
}
