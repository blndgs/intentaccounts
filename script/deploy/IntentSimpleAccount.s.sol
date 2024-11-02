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

    error PreviouslyDeployed(address at);

    // CREATE2 address computation for factory
    function predictFactoryAddress(bytes32 salt) public pure returns (address) {
        bytes memory creationCode =
            abi.encodePacked(type(IntentSimpleAccountFactory).creationCode, abi.encode(IEntryPoint(ENTRYPOINT)));

        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), FORGE_CREATE2_DEPLOYER, salt, keccak256(creationCode)));
        return address(uint160(uint256(hash)));
    }

    function run() public {
        // Load factory deployment parameters
        bytes32 factorySalt = bytes32(vm.envUint("FACTORY_SALT"));
        uint256 factoryDeployerKey = vm.envUint("FACTORY_DEPLOYER_KEY");
        address factoryDeployer = vm.addr(factoryDeployerKey);

        // Load wallet creation parameters
        uint256 walletSalt = vm.envUint("WALLET_SALT");
        uint256 walletDeployerKey = vm.envUint("WALLET_DEPLOYER_KEY");
        address walletDeployer = vm.addr(walletDeployerKey);

        // Log initial state
        console2.log("Factory Deployer:", factoryDeployer);
        console2.log("Factory Salt:", uint256(factorySalt));
        console2.log("Waller deployer:", walletDeployer);
        console2.log("Wallet Salt:", walletSalt);

        // Predict factory address using the Create2Deployer address
        address predictedFactoryAddress = predictFactoryAddress(factorySalt);

        // Deploy or get factory
        IntentSimpleAccountFactory factory;
        if (predictedFactoryAddress.code.length > 0) {
            factory = IntentSimpleAccountFactory(predictedFactoryAddress);
            console2.log("Using existing factory at:", address(factory));
        } else {
            // Check if address was previously used and self-destructed
            uint256 nonce = vm.getNonce(predictedFactoryAddress);
            if (nonce > 0) {
                revert PreviouslyDeployed(predictedFactoryAddress);
            }

            // Deploy factory using dedicated deployer key
            vm.broadcast(factoryDeployerKey);
            factory = new IntentSimpleAccountFactory{salt: factorySalt}(IEntryPoint(ENTRYPOINT));
            console2.log("Deployed new factory at:", address(factory));

            require(address(factory) == predictedFactoryAddress, "Factory address mismatch");
        }

        // Switch to walletDeployer for account creation
        vm.startBroadcast(walletDeployerKey);

        // Predict account address using factory's createAccount salt mechanism
        address predictedAccountAddress = factory.getAddress(walletDeployer, walletSalt);
        console2.log("Predicted account address:", predictedAccountAddress);

        // Create or get account
        if (predictedAccountAddress.code.length > 0) {
            console2.log("Account already exists at:", predictedAccountAddress);
        } else {
            // Check if account address was previously used and self-destructed
            uint256 nonce = vm.getNonce(predictedAccountAddress);
            if (nonce > 0) {
                revert PreviouslyDeployed(predictedAccountAddress);
            }

            IntentSimpleAccount account = factory.createAccount(walletDeployer, walletSalt);
            console2.log("Deployed new account at:", address(account));

            require(address(account) == predictedAccountAddress, "Account address mismatch");
        }

        vm.stopBroadcast();
    }
}
