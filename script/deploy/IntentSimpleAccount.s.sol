// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "src/IntentSimpleAccountFactory.sol";
import "src/IntentSimpleAccount.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/Script.sol";

/**
 * @title DeploySimpleAccount
 * @dev This contract deploys a SimpleAccount and its factory with deterministic addresses
 * across EVM networks. It uses a dedicated private key with zero nonce for factory deployment
 * to ensure same addresses across chains.
 *
 * Environment Variables Required:
 * - FACTORY_DEPLOYER_KEY: Dedicated private key for factory deployment (MUST have 0 nonce)
 * - WALLET_DEPLOYER_KEY: Private key for account creation and operations
 * - FACTORY_SALT: The salt value for deterministic factory deployment
 * - WALLET_SALT: Salt for deterministic account creation
 *
 * - Different use cases for salts:
 * - Factory salt - for infrastructure/deployment coordination
 * - bytes32 factorySalt = keccak256("INTENT_SIMPLE_ACCOUNT_FACTORY_V1");
 * - Wallet salts - for user account management
 * - uint256 primaryWalletSalt = 0;  // User's main account
 * - uint256 backupWalletSalt = 1;   // Backup account
 * - uint256 gameWalletSalt = 100;   // Gaming specific account
 * -
 * - All these accounts will be deterministic across chains because:
 * - 1. Factory address is same (due to factorySalt)
 * - 2. Owner address is same
 * - 3. Wallet salt is same
 *
 * CLI examples:
 *  MAINNET
 *  export VERIFIER_URL=https://api.polygonscan.com/api
 *  -- OR --
 *  TENDERLY
 *  export VERIFIER_URL=https://virtual.mainnet.rpc.tenderly.co/c5ed9a3b-7ad5-4d6a-8e4b-76a4b00ba6ea/verify/etherscan
 * RPC_URL=https://bsc-mainnet.nodereal.io/v1/12445b762b994082bb3b7b7c8788b085
 * FACTORY_DEPLOYER_KEY=   # Must have 0 nonce for deterministic addresses
 * WALLET_DEPLOYER_KEY=   # For account wallet deployment
 * ETHEREUMSCAN_API_KEY=
 *
 * Deploy command:
 * forge script script/deploy/IntentSimpleAccount.s.sol \
 *    --rpc-url $RPC_URL \
 *    --broadcast \
 *    --slow \
 *    --etherscan-api-key $ETHEREUMSCAN_API_KEY \
 *    --verify \
 *    --verifier-url $VERIFIER_URL \
 *    --ffi -vvvv
 */
contract DeploySimpleAccount is Script {
    address internal constant ENTRYPOINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address internal constant FORGE_CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    error DeploymentFailed(string reason);
    error AccountCreationFailed(address factory, string reason);
    error InvalidDeployment(address expected, address actual);

    event Deployed(
        address indexed implementation, address indexed factory, address indexed proxy, bytes initData, uint256 gasUsed
    );

    function predictFactoryAddress(bytes32 salt) public pure returns (address) {
        bytes memory creationCode =
            abi.encodePacked(type(IntentSimpleAccountFactory).creationCode, abi.encode(IEntryPoint(ENTRYPOINT)));
        bytes32 codeHash = keccak256(creationCode);
        console2.log("Creation Code Hash:");
        console2.logBytes32(codeHash);

        return Create2.computeAddress(salt, codeHash, FORGE_CREATE2_DEPLOYER);
    }

    function run() public {
        // Load deployment parameters
        bytes32 factorySalt = bytes32(vm.envUint("FACTORY_SALT"));
        uint256 walletOwnerKey = vm.envUint("WALLET_OWNER_KEY");
        address walletOwner = vm.addr(walletOwnerKey);
        uint256 walletSalt = vm.envUint("WALLET_SALT");

        // Log initial configuration
        console2.log("=== Deployment Configuration ===");
        console2.log("Wallet Owner (Deployer):", walletOwner);
        console2.log("Factory Salt:", uint256(factorySalt));
        console2.log("Wallet Salt:", walletSalt);
        console2.log("EntryPoint:", ENTRYPOINT);
        console2.log("Create2 Deployer:", FORGE_CREATE2_DEPLOYER);
        console2.log("============================\n");

        // Predict factory address
        address predictedFactory = predictFactoryAddress(factorySalt);
        console2.log("Predicted Factory Address:", predictedFactory);

        // Start deployment tracking
        uint256 startGas = gasleft();

        console2.log("\n=== Starting Deployment ===");

        // Deploy the factory and create the account using the Wallet Owner Account
        vm.startBroadcast(walletOwnerKey);
        (address implementation, address factoryAddr, address proxyAddr, bytes memory initData) =
            deployContracts(factorySalt, predictedFactory, walletSalt, walletOwner);
        vm.stopBroadcast();

        uint256 gasUsed = startGas - gasleft();

        // Log deployment results
        console2.log("\n=== Deployment Results ===");
        console2.log("Implementation:", implementation);
        console2.log("Factory:", factoryAddr);
        console2.log("Account Proxy:", proxyAddr);
        console2.log("Gas Used:", gasUsed);

        // Log contract sizes for verification
        console2.log("\n=== Contract Sizes ===");
        console2.log("Implementation Size:", implementation.code.length);
        console2.log("Factory Size:", factoryAddr.code.length);
        console2.log("Proxy Size:", proxyAddr.code.length);

        emit Deployed(implementation, factoryAddr, proxyAddr, initData, gasUsed);

        console2.log("\n=== Deployment Successful ===");
    }

    function deployContracts(bytes32 factorySalt, address predictedFactory, uint256 walletSalt, address walletOwner)
        internal
        returns (address implementation, address factoryAddr, address proxyAddr, bytes memory initData)
    {
        IntentSimpleAccountFactory factory;

        // Deploy or get factory
        if (predictedFactory.code.length == 0) {
            console2.log("Deploying new factory...");
            factory = new IntentSimpleAccountFactory{salt: factorySalt}(IEntryPoint(ENTRYPOINT));
            if (address(factory) != predictedFactory) {
                revert InvalidDeployment(predictedFactory, address(factory));
            }
            factoryAddr = address(factory);
            implementation = address(factory.accountImplementation());
            console2.log("Factory deployed at:", factoryAddr);
            console2.log("Implementation deployed at:", implementation);
        } else {
            console2.log("Using existing factory at:", predictedFactory);
            factory = IntentSimpleAccountFactory(predictedFactory);
            factoryAddr = predictedFactory;
            implementation = address(factory.accountImplementation());
            console2.log("Using existing implementation at:", implementation);
        }

        require(implementation.code.length > 0, "Implementation deployment failed");
        require(factoryAddr.code.length > 0, "Factory deployment failed");

        // Create account with error handling for external call
        console2.log("\nCreating account for owner:", walletOwner);
        try factory.createAccount(walletOwner, walletSalt) returns (IntentSimpleAccount account) {
            proxyAddr = address(account);
            initData = abi.encodeCall(IntentSimpleAccount.initialize, (walletOwner));
            console2.log("Account proxy deployed at:", proxyAddr);
        } catch Error(string memory reason) {
            console2.log("\nAccount creation failed with reason:", reason);
            revert AccountCreationFailed(address(factory), reason);
        } catch (bytes memory lowLevelData) {
            // Handle low-level error (e.g., revert without a message)
            console2.log("\nAccount creation failed with low-level error");
            if (lowLevelData.length > 0) {
                string memory reason = _getRevertMsg(lowLevelData);
                console2.log("Revert reason:", reason);
                revert AccountCreationFailed(address(factory), reason);
            } else {
                revert AccountCreationFailed(address(factory), "Unknown error");
            }
        }

        require(proxyAddr.code.length > 0, "Proxy deployment failed");

        console2.log("\nAccount deployment verified successfully");
    }

    // Helper function to extract revert message from low-level bytes
    function _getRevertMsg(bytes memory _returnData) internal pure returns (string memory) {
        // If the _returnData length is less than 68, then the transaction failed silently (without a revert message)
        if (_returnData.length < 68) return "Transaction reverted silently";

        assembly {
            // Slice the sighash
            _returnData := add(_returnData, 0x04)
        }
        return abi.decode(_returnData, (string)); // All that remains is the revert string
    }
}
