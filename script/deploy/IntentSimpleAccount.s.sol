// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "src/IntentSimpleAccountFactory.sol";
import "src/IntentSimpleAccount.sol";
import "src/IntentSimpleAccountFactoryDeployer.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/Script.sol";

/**
 * @title DeploySimpleAccount
 * @dev This contract deploys a SimpleAccount and its factory with deterministic addresses
 * across EVM networks. It uses a dedicated private key with zero nonce for factory deployment
 * to ensure same addresses across chains.
 *
 * Environment Variables Required:
 * - NETWORK: The network to deploy to (e.g., ETHEREUM, POLYGON, BSC)
 * - DEPLOYER_KEY: Dedicated private key for factory deployment (MUST have 0 nonce)
 * - OPERATOR_KEY: Private key for account creation and operations
 * - {NETWORK}_SALT: The salt value for deterministic deployment
 *
 * CLI examples:
 * MAINNET
 * export VERIFIER_URL=https://api.polygonscan.com/api
 * TENDERLY
 * export VERIFIER_URL=https://virtual.mainnet.rpc.tenderly.co/c5ed9a3b-7ad5-4d6a-8e4b-76a4b00ba6ea/verify/etherscan
 * RPC_URL=https://bsc-mainnet.nodereal.io/v1/12445b762b994082bb3b7b7c8788b085
 * DEPLOYER_KEY=   # Must have 0 nonce for deterministic addresses
 * OPERATOR_KEY=   # For account operations
 * ETHEREUMSCAN_API_KEY=
 *
 * Deploy command:
 * forge script script/deploy/IntentSimpleAccount.s.sol \
 *    --rpc-url $RPC_URL \
 *    --broadcast \
 *    --slow \
 *    --private-key $OPERATOR_KEY \
 *    --etherscan-api-key $ETHEREUMSCAN_API_KEY \
 *    --verify \
 *    --verifier-url $VERIFIER_URL \
 *    --ffi -vvvv
 */
contract DeploySimpleAccount is Script {
    address internal constant ENTRYPOINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    string internal _network;

    error NonZeroNonce(uint256 nonce);

    function setUp() public {
        _network = vm.envString("NETWORK");
    }

    function predictFactoryAddress(address deployer, bytes32 salt) public view returns (address) {
        bytes memory creationCode = abi.encodePacked(
            type(IntentSimpleAccountFactory).creationCode,
            abi.encode(IEntryPoint(ENTRYPOINT), salt)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                deployer,
                salt,
                keccak256(creationCode)
            )
        );
        return address(uint160(uint256(hash)));
    }

    function run() public {
        // Get network-specific salt
        string memory saltEnv = string(abi.encodePacked(_network, "_SALT"));
        uint256 saltUint = vm.envUint(saltEnv);
        bytes32 salt = bytes32(saltUint);

        // Get factory deployer key and address
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address factoryDeployer = vm.addr(deployerKey);
        
        // Get operator key and address (for account creation and general operations)
        uint256 operatorKey = vm.envUint("OPERATOR_KEY");
        address operator = vm.addr(operatorKey);

        // Log initial state
        console2.log("Network:", _network);
        console2.log("Factory Deployer:", factoryDeployer);
        console2.log("Operator:", operator);
        console2.log("Salt:", uint256(salt));

        // Check deployer nonce - HALT if not 0
        uint256 deployerNonce = vm.getNonce(factoryDeployer);
        if (deployerNonce != 0) {
            revert NonZeroNonce(deployerNonce);
        }

        // Predict factory address
        address predictedFactoryAddress = predictFactoryAddress(factoryDeployer, salt);
        console2.log("Predicted factory address:", predictedFactoryAddress);

        // Deploy or get factory
        IntentSimpleAccountFactory factory;
        if (predictedFactoryAddress.code.length > 0) {
            factory = IntentSimpleAccountFactory(predictedFactoryAddress);
            console2.log("Using existing factory at:", address(factory));
        } else {
            // Deploy factory using dedicated deployer key
            vm.broadcast(deployerKey);
            factory = new IntentSimpleAccountFactory{salt: salt}(IEntryPoint(ENTRYPOINT));
            console2.log("Deployed new factory at:", address(factory));
            
            require(
                address(factory) == predictedFactoryAddress,
                "Factory address mismatch"
            );
        }

        // Switch to operator for account creation
        vm.startBroadcast(operatorKey);

        // Predict account address
        address predictedAccountAddress = factory.getAddress(operator, saltUint);
        console2.log("Predicted account address:", predictedAccountAddress);

        // Create or get account
        if (predictedAccountAddress.code.length > 0) {
            console2.log("Account already exists at:", predictedAccountAddress);
        } else {
            IntentSimpleAccount account = factory.createAccount(operator, saltUint);
            console2.log("Deployed new account at:", address(account));
            
            require(
                address(account) == predictedAccountAddress,
                "Account address mismatch"
            );
        }

        vm.stopBroadcast();
    }
}