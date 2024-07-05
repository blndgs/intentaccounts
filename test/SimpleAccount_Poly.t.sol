// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/IntentSimpleAccount.sol";
import "../src/IntentSimpleAccountFactory.sol";
import "@account-abstraction/interfaces/IEntryPoint.sol";
import "@account-abstraction/core/EntryPoint.sol";
import "forge-std/interfaces/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./TestSimpleAccountHelper.sol";

contract SimpleAccounPolygonTest is Test {
    using Strings for bytes32;
    using UserOperationLib for UserOperation;
    using TestSimpleAccountHelper for UserOperation;

    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 public constant MUMBAI_CHAIN_ID = 80001;
    uint256 public constant POLYGON_CHAIN_ID = 137;
    uint256 mumbaiFork;

    using ECDSA for bytes32;

    IntentSimpleAccountFactory factory;
    IntentSimpleAccount simpleAccount;
    uint256 salt;
    IEntryPoint public entryPoint;
    address public ownerAddress;
    uint256 public ownerPrivateKey;
    IERC20 public token;

    string network;

    function setUp() public {
        string memory privateKeyEnv = string(abi.encodePacked(network, "POLYGON_PRIVATE_KEY"));
        string memory privateKeyString = vm.envString(privateKeyEnv);

        // Derive the Ethereum address from the private key
        ownerPrivateKey = vm.parseUint(privateKeyString);
        ownerAddress = vm.addr(ownerPrivateKey);
        assertEq(ownerAddress, 0xc9164f44661d83d01CbB69C0b0E471280f446099, "Owner address should match");

        // Create a VM instance for the MUMBAI fork
        string memory urlEnv = string(abi.encodePacked(network, "POLYGON_RPC_URL"));
        mumbaiFork = vm.createSelectFork(vm.envString(urlEnv));
        assert(MUMBAI_CHAIN_ID == block.chainid || POLYGON_CHAIN_ID == block.chainid);

        vm.startPrank(ownerAddress);

        // Deploy the EntryPoint contract or use an existing one
        entryPoint = EntryPoint(payable(ENTRYPOINT_V06));
        console2.log("EntryPoint deployed at:", address(entryPoint));

        token = IERC20(0x9d34f236bDDF1B9De014312599d9C9Ec8af1Bc48);

        // Create a unique salt for the account creation
        string memory saltEnv = string(abi.encodePacked(network, "POLYGON_SALT"));
        salt = vm.envUint(saltEnv);
        console2.log("Salt:", salt);

        uint256 startGas = gasleft();

        // Sync the factory with the deployed contract at Mannet
        factory = IntentSimpleAccountFactory(0x42E60c23aCe33c23e0945a07f6e2c1E53843a1d5);
        console2.log("IntentSimpleAccountFactory synced at:", address(factory));
        uint256 endGas = gasleft();
        console2.log("Gas used for Factory sync: ", startGas - endGas);
        startGas = endGas;

        // Use the factory to create a new SimpleAccount instance
        simpleAccount = IntentSimpleAccount(payable (0x89D05CEc8CDdc6801feD02DDB54F0dA31953a1fC));
        console2.log("SimpleAccount wallet created at:", address(simpleAccount));
        console2.log("Gas used for wallet creation: ", startGas - endGas);
        startGas = endGas;
    }

    // Signature Steps:
    // 1. Pack the UserOperation object
    //    function pack(UserOperation calldata userOp) internal pure returns (bytes memory ret) {
    //        address sender = getSender(userOp);
    //        uint256 nonce = userOp.nonce;
    //        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
    //        bytes32 hashCallData = calldataKeccak(userOp.callData);
    //        uint256 callGasLimit = userOp.callGasLimit;
    //        uint256 verificationGasLimit = userOp.verificationGasLimit;
    //        uint256 preVerificationGas = userOp.preVerificationGas;
    //        uint256 maxFeePerGas = userOp.maxFeePerGas;
    //        uint256 maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
    //        bytes32 hashPaymasterAndData = calldataKeccak(userOp.paymasterAndData);
    //
    //        return abi.encode(
    //            sender, nonce,
    //            hashInitCode, hashCallData,
    //            callGasLimit, verificationGasLimit, preVerificationGas,
    //            maxFeePerGas, maxPriorityFeePerGas,
    //            hashPaymasterAndData
    //        );
    //    }
    // 2. Hash the packed UserOperation object
    // return keccak256(pack(userOp));

    // 3. generate a hash Id
    // return keccak256(abi.encode(userOp.hash(), address(EntryPoint), block.chainid));

    // 4. Crete an Ethereum Text Signed Message, from the `hash`
    // ethSigned = userOpHash.toEthSignedMessageHash()
    //    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 message) {
    //        // 32 is the length in bytes of hash,
    //        // enforced by the type signature above
    //        /// @solidity memory-safe-assembly
    //        assembly {
    //            mstore(0x00, "\x19Ethereum Signed Message:\n32")
    //            mstore(0x1c, hash)
    //            message := keccak256(0x00, 0x3c)
    //        }
    //    }

    // 5. Sign the Eth Signed text with the owner's private key
    // vm.sign(ownerPrivateKey, ethSigned)

    function testSimpleAccountAddress() public {
        // verify the created account's address matches the expected counterfactual address
        address generatedAddress = factory.getAddress(ownerAddress, salt);
        assertEq(address(simpleAccount), generatedAddress, "Account address does not match expected address");
    }

    function testValidateSignature() public {
        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: ownerAddress,
            nonce: 0,
            initCode: "",
            callData: "",
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: "",
            signature: ""
        });

        // Generate the signature
        bytes memory generatedSignature = generateSignature(userOp, block.chainid);

        // Update the user operation with the generated signature
        userOp.signature = generatedSignature;

        // Test the _validateSignature method
        uint256 result = simpleAccount.validateSignature(userOp, bytes32(0));
        assertEq(result, 0, "Signature should be valid");
    }

    function testValidateMumbaiVanillaOp() public {
        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: 0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47,
            nonce: 0x8,
            initCode: bytes(hex""),
            callData: bytes(hex""),
            callGasLimit: 0x2dc6c0,
            verificationGasLimit: 0x2dc6c0,
            preVerificationGas: 0xbb70,
            maxFeePerGas: 0x7e498f31e,
            maxPriorityFeePerGas: 0x7e498f300,
            paymasterAndData: bytes(hex""),
            signature: bytes(
                hex"92f25342760a82b7e5649ed7c6d2d7cb93c0093f66c916d7e57de4af0ae00e2b0524bf364778c6b30c491354be332a1ce521e8a57c5e26f94f8069a404520e931b"
                )
        });

        userOp.nonce = simpleAccount.getNonce();

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        verifySignature(userOp);
    }

    function testValidateMumbaiLongCallData() public {
        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: 0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47,
            nonce: 0xb,
            initCode: bytes(hex""),
            callData: bytes(
                hex"b61d27f60000000000000000000000008c42cf13fbea2ac15b0fe5a5f3cf35eec65d7d7d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000dc4c7cd97480000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000012000000000000000000000000066c0aee289c4d332302dda4ded0c0cdc3784939a0000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000053a3e3f4800000000000000000000000067297ee4eb097e072b4ab6f1620268061ae804640000000000000000000000002397d2fde31c5704b02ac1ec9b770f23d70d8ec4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000149000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006352a56caadc4f1e25cd6c75970fa768a3304e6466c0aee289c4d332302dda4ded0c0cdc3784939a562e362876c8aee4744fc2c6aac8394c312d215d1f9840a85d5af5bf1d1762f925bdaddc4201f9840000000000000000000000000000000000000000000000000000000439689a920000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000006596a37066c0aee289c4d332302dda4ded0c0cdc3784939a1dfa0ff0b2e64429acf334d64097b28000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004109ffe4bb46d80a7da156ae6795558927a3613cc6073ddad94296335191660e673c7696803900ccd4b4ba1012a198259f0ce8c3873247ce209a326185458cede61c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000a0490411a32000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000001f9840a85d5af5bf1d1762f925bdaddc4201f984000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d000000000000000000000000dafd66636e2561b0284edde37e42d192f2844d40000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a760000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000439689a930000000000000000000000000000000000000000000000000000000547c2c13700000000000000000000000000000000000000000000000000000000000000020000000000000000000000008ba3c3f7334375f95c128bc6a9b8fc42e870f160000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000004a000000000000000000000000000000000000000000000000000000000000005c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064cac460ee00000000000000003b6d0340dafd66636e2561b0284edde37e42d192f2844d400000000000000000000000001f9840a85d5af5bf1d1762f925bdaddc4201f984000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000002449f865422000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000104e5b07cdb0000000000000000000000004e4abd1c111c08b3a05feed46556496e6a3fd89300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a00000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000002ec02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000bb8562e362876c8aee4744fc2c6aac8394c312d215d0000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000648a6a1e85000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d000000000000000000000000353c1f0bc78fbbc245b3c93ef77b1dcc5b77d2a00000000000000000000000000000000000000000000000000000000547c2c13700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a49f865422000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d00000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064d1660f99000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a76000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                ),
            callGasLimit: 0x88b8,
            verificationGasLimit: 0x11170,
            preVerificationGas: 0x5208,
            maxFeePerGas: 0x150c428820,
            maxPriorityFeePerGas: 0x150c428800,
            paymasterAndData: bytes(hex""),
            signature: bytes(
                hex"74199499de42614e0172afc5781179682f311ed1ec8b369d5a4d8bae4e68f3387e9cab11473b4fb65932e4a8812793f6b7e80a9700855fde454109ceeac02e911b"
                )
        });

        userOp.nonce = simpleAccount.getNonce();

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        verifySignature(userOp);
    }

    function testValidate_UnsolvedIntentOp() public {
        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: 0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47,
            nonce: 0xb,
            initCode: bytes(hex""),
            callData: bytes(
                '{"chainId":80001, "sender":"0x0A7199a96fdf0252E09F76545c1eF2be3692F46b","kind":"swap","hash":"","sellToken":"TokenA","buyToken":"TokenB","sellAmount":10,"buyAmount":5,"partiallyFillable":false,"status":"Received","createdAt":0,"expirationAt":0}'
                ),
            callGasLimit: 0x88b8,
            verificationGasLimit: 0x11170,
            preVerificationGas: 0x5208,
            maxFeePerGas: 0x150c428820,
            maxPriorityFeePerGas: 0x150c428800,
            paymasterAndData: bytes(hex""),
            signature: bytes(
                hex"8a2e15b3a0b4964c99e8929d26b081c94b0b284f9a67052019450911a9ee1dd964c862655d9ffc0b97350f5987a6793085adc8cc2297dc97e4b21666539148171b"
                )
        });

        userOp.nonce = simpleAccount.getNonce();

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        verifySignature(userOp);
    }

    function testValidate_UnsolvedIntent0GasOp() public {
        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: 0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47,
            nonce: 0xb,
            initCode: bytes(hex""),
            callData: bytes(
                '{"chainId":80001, "sender":"0x0A7199a96fdf0252E09F76545c1eF2be3692F46b","kind":"swap","hash":"","sellToken":"TokenA","buyToken":"TokenB","sellAmount":10,"buyAmount":5,"partiallyFillable":false,"status":"Received","createdAt":0,"expirationAt":0}'
                ),
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(
                hex"1b2c01e59028d70e881fc913570014ca4d693e29725dbbb5cd56cdc8b8f5007e6188fd6afd3482d65703c3a884195712c901aebf3a0964de04367e8c827340db1b"
                )
        });

        userOp.nonce = simpleAccount.getNonce();

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        verifySignature(userOp);
    }

    function testValidate_SolvedNilIntentOp() public {
        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: address(0),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes("{}<intent-end>0x"),
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(
                hex"1b81c8280ec9fbf3009c650a67eadac8ab53ab645f55bdb927a870b40649904f7d1a5e9bd75b7e362625f05874f53d9e071cdc27baa43fc5a89b1338f24a9c7b1b"
                )
        });

        userOp.nonce = simpleAccount.getNonce();

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        verifySignature(userOp);
    }

    function testValidate_SolvedIntentOpNilSolution() public {
        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: 0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47,
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                '{"chainId":80001, "sender":"0x0A7199a96fdf0252E09F76545c1eF2be3692F46b","kind":"swap","hash":"","sellToken":"TokenA","buyToken":"TokenB","sellAmount":10,"buyAmount":5,"partiallyFillable":false,"status":"Received","createdAt":0,"expirationAt":0}<intent-end>0x'
                ),
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(
                hex"e14ea21c8d6478388bfc9e5f1bf9a0d45fe1359fbfeac193e8b504be2db9fc317f6c6b06bff42328af64f6be85a31e729d2cab6c6b83ebf3ef12bc4cc344e9c31c"
                )
        });

        userOp.nonce = simpleAccount.getNonce();

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        verifySignature(userOp);
    }

    function testValidate_SolvedIntentOp() public {
        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: 0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47,
            nonce: 0xb,
            initCode: bytes(hex""),
            callData: bytes(
                '{"chainId":80001, "sender":"0x0A7199a96fdf0252E09F76545c1eF2be3692F46b","kind":"swap","hash":"","sellToken":"TokenA","buyToken":"TokenB","sellAmount":10,"buyAmount":5,"partiallyFillable":false,"status":"Received","createdAt":0,"expirationAt":0}<intent-end>0xb61d27f60000000000000000000000009d34f236bddf1b9de014312599d9c9ec8af1bc48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000d7b21a844f3a41c91a73d3f87b83fa93bb6cb518000000000000000000000000000000000000000000000000000000002faf080000000000000000000000000000000000000000000000000000000000'
                ),
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(
                hex"1b2c01e59028d70e881fc913570014ca4d693e29725dbbb5cd56cdc8b8f5007e6188fd6afd3482d65703c3a884195712c901aebf3a0964de04367e8c827340db1b"
                )
        });

        userOp.nonce = simpleAccount.getNonce();

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        verifySignature(userOp);
    }

    function testExecute_EmptyOp() public {
        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: address(simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(hex""),
            callGasLimit: 0,
            verificationGasLimit: 70000,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = simpleAccount.getNonce();

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;
        entryPoint.handleOps(userOps, payable(ownerAddress));
    }

    function showBalances(address anAddress, string memory outMsg) public view {
        console2.log("---------------", outMsg);
        console2.log("For address:", anAddress);
        console2.log("Ether balance:", anAddress.balance);
        console2.log("Entrypoint balance:", entryPoint.balanceOf(anAddress));
    }

    function testExecute_vanillaUserOp() public {
        showBalances(ownerAddress, "Before userOp execution");
        showBalances(address(simpleAccount), "Before userOp execution");

        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: address(simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                "0xb61d27f60000000000000000000000009d34f236bddf1b9de014312599d9c9ec8af1bc48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000d7b21a844f3a41c91a73d3f87b83fa93bb6cb518000000000000000000000000000000000000000000000000000000002faf080000000000000000000000000000000000000000000000000000000000"
                ),
            callGasLimit: 0,
            verificationGasLimit: 300000,
            preVerificationGas: 300000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = simpleAccount.getNonce();

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;
        entryPoint.handleOps(userOps, payable(ownerAddress));

        showBalances(ownerAddress, "After userOp execution");
        showBalances(address(simpleAccount), "After userOp execution");
    }

    function testValidateExecute_SolvedOpReverted() public {
        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: address(simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                '{"chainId":80001, "sender":"0x0A7199a96fdf0252E09F76545c1eF2be3692F46b","kind":"swap","hash":"","sellToken":"TokenA","buyToken":"TokenB","sellAmount":10,"buyAmount":5,"partiallyFillable":false,"status":"Received","createdAt":0,"expirationAt":0}<intent-end>0xb61d27f60000000000000000000000009d34f236bddf1b9de014312599d9c9ec8af1bc48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000d7b21a844f3a41c91a73d3f87b83fa93bb6cb518000000000000000000000000000000000000000000000000000000002faf080000000000000000000000000000000000000000000000000000000000'
                ),
            callGasLimit: 0,
            verificationGasLimit: 300000,
            preVerificationGas: 300000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = simpleAccount.getNonce();

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        vm.stopPrank();
        vm.prank(ENTRYPOINT_V06);
        simpleAccount.validateUserOp(userOp, bytes32(0), 0);
        vm.startPrank(ownerAddress);
        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        vm.expectEmit(false, true, true, false, 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
        // successful request with ** reverted sender transaction **
        emit IEntryPoint.UserOperationEvent(0, address(simpleAccount), address(0), 0, false, 0, 0);
        entryPoint.handleOps(userOps, payable(ownerAddress));
    }

    function testValidateExecute_SolvedOpNewCallData() public {
        console2.log("sender:", address(simpleAccount));
        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: address(simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                "{\"chainId\":80001, \"sender\":\"0x18Dd70639de2ca9146C32f9c84B90A68bBDaAA96\",\"kind\":\"swap\",\"hash\":\"\",\"sellToken\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"buyToken\":\"0xc2132D05D31c914a87C6611C10748AEb04B58e8F\",\"sellAmount\":10,\"buyAmount\":5,\"partiallyFillable\":false,\"status\":\"Received\",\"createdAt\":0,\"expirationAt\":0}"
                ),
            callGasLimit: 300000,
            verificationGasLimit: 300000,
            preVerificationGas: 300000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = simpleAccount.getNonce();

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        userOp.signature = bytes(
            abi.encodePacked(
                userOp.signature,
                userOp.callData
            )
        );
        // Solve Intent userOp
        userOp.callData = bytes(
            hex"b61d27f60000000000000000000000009d34f236bddf1b9de014312599d9c9ec8af1bc48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000d7b21a844f3a41c91a73d3f87b83fa93bb6cb518000000000000000000000000000000000000000000000000000000000000037800000000000000000000000000000000000000000000000000000000"
        );

        verifySignature(userOp);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;
        entryPoint.handleOps(userOps, payable(ownerAddress));
    }

    function testValidateExecute_SolverIntentOp() public {
        console2.log("sender:", address(simpleAccount));

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: address(simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                "{\"chainId\":80001, \"sender\":\"0x18Dd70639de2ca9146C32f9c84B90A68bBDaAA96\",\"kind\":\"swap\",\"hash\":\"\",\"sellToken\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"buyToken\":\"0xc2132D05D31c914a87C6611C10748AEb04B58e8F\",\"sellAmount\":10,\"buyAmount\":5,\"partiallyFillable\":false,\"status\":\"Received\",\"createdAt\":0,\"expirationAt\":0}"
                ),
            callGasLimit: 300000,
            verificationGasLimit: 300000,
            preVerificationGas: 300000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = simpleAccount.getNonce();
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
            hex"b61d27f6000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a76000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000364c7cd97480000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000012000000000000000000000000042d4e9ee3f725c84b7934e4fda64f2be0f8031300000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000087cb219500000000000000000000000067297ee4eb097e072b4ab6f1620268061ae804640000000000000000000000002397d2fde31c5704b02ac1ec9b770f23d70d8ec4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000149000000000000000000000000000000000000000000000000000ab1f0e9908efdff8ba4d1fc3762f6154cc942ccf30049a2a0cec65b0711eee0c6366aa35a98b14fd8b4b4c6d1d04c42d4e9ee3f725c84b7934e4fda64f2be0f803130dac17f958d2ee523a2206206994597c13d831ec7c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000000000000000000000000000000892a46200000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000065bfc91a42d4e9ee3f725c84b7934e4fda64f2be0f80313062d65d760e2c4c79a53434564574d2812dfabbb6d9e55b8ab403c6da20ea5c95df76cacc6b22c29c10a855f6c9758df816d33be31be64ce6e083c1e88733cdaca6713de609c626a5aec577750af90aca1b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041416896cf6aafa421b8c6bc438ed2147791e29741e78e8ac2fa69f1e8a7491a51069f14313f6aa9dfba696b05f1bd37170f5b8c4d2ec4830dedbec11961126b751c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
        console2.log("intent signature:");
        console2.logBytes(userOp.signature);

        // 6. Bundler submits solved userOp on-chain

        verifySignature(userOp);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        // 7. entryPoint executes the intent userOp
        entryPoint.handleOps(userOps, payable(ownerAddress));
    }

    function testValidateExecute_SolverIntentOpNewModel() public {
        console2.log("sender:", address(simpleAccount));

        // 1. SDK setups the unsigned Intent UserOp
        UserOperation memory userOp = UserOperation({
            sender: address(simpleAccount),
            nonce: 0,
            initCode: bytes(hex""),
            callData: bytes(
                "{\"chainId\":80001, \"sender\":\"0x18Dd70639de2ca9146C32f9c84B90A68bBDaAA96\",\"kind\":\"swap\",\"hash\":\"\",\"sellToken\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"buyToken\":\"0xc2132D05D31c914a87C6611C10748AEb04B58e8F\",\"sellAmount\":10,\"buyAmount\":5,\"partiallyFillable\":false,\"status\":\"Received\",\"createdAt\":0,\"expirationAt\":0}"
                ),
            callGasLimit: 300000,
            verificationGasLimit: 300000,
            preVerificationGas: 300000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(hex""),
            signature: bytes(hex"")
        });

        userOp.nonce = simpleAccount.getNonce();
        console2.log("nonce:", userOp.nonce);

        // 2. SDK signs the intent userOp
        userOp.signature = generateSignature(userOp, block.chainid);
        console2.log("signature:");
        console2.logBytes(userOp.signature);

        // 3. SDK submits to Bundler...
        // 4. Bundler submits userOp to the Solver

        // 5. Solver solves Intent userOp
        userOp.callData = bytes(
            hex"b61d27f60000000000000000000000008c42cf13fbea2ac15b0fe5a5f3cf35eec65d7d7d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000002704c7cd9748000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000a7199a96fdf0252e09f76545c1ef2be3692f46b0000000000000000000000000000000000000000000000004563918244f40000000000000000000000000000000000000000000000000000000000000049149200000000000000000000000067297ee4eb097e072b4ab6f1620268061ae8046400000000000000000000000048e8d45ef08782da3072a19e153df9830d7d801e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000149000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006352a56caadc4f1e25cd6c75970fa768a3304e640a7199a96fdf0252e09f76545c1ef2be3692f46bc2132d05d31c914a87c6611c10748aeb04b58e8f0d500b1d8e8ef31e21c99d1db9a6444d3adf127000000000000000000000000000000000000000000000000000000000003b0e090000000000000000000000000000000000000000000000004563918244f400000000000000000000000000000000000000000000000000000000000065d4de680a7199a96fdf0252e09f76545c1ef2be3692f46b02176176eebf4588bdb789fabc268e690000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000414b7e5e1a25ef9b465f5687e108fb122f23aae0003ecac3348b38c7563ec110321bc78da7ba8ec09d50252f5efdce547a45b4df3f89f3a661b872236b745d7f591c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000234490411a320000000000000000000000001e82ad8a12068a85fcb96368463b434e77b21201000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf1270000000000000000000000000c2132d05d31c914a87c6611c10748aeb04b58e8f0000000000000000000000001e82ad8a12068a85fcb96368463b434e77b212010000000000000000000000008c42cf13fbea2ac15b0fe5a5f3cf35eec65d7d7d0000000000000000000000000000000000000000000000004563918244f4000000000000000000000000000000000000000000000000000000000000003b0e0a000000000000000000000000000000000000000000000000000000000049d18c00000000000000000000000000000000000000000000000000000000000000020000000000000000000000008ba3c3f7334375f95c128bc6a9b8fc42e870f16000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d00000000000000000000000000000000000000000000000000000000000001a0000000000000000000000000000000000000000000000000000000000000062000000000000000000000000000000000000000000000000000000000000007800000000000000000000000000000000000000000000000000000000000000c6000000000000000000000000000000000000000000000000000000000000010e0000000000000000000000000000000000000000000000000000000000000124000000000000000000000000000000000000000000000000000000000000014a000000000000000000000000000000000000000000000000000000000000015c00000000000000000000000000000000000000000000000000000000000001a400000000000000000000000000000000000000000000000000000000000001ba00000000000000000000000000000000000000000000000000000000000001cc00000000000000000000000000000000000000000000000000000000000001de00000000000000000000000000000000000000000000000000000000000001f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000003c451a743160000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf1270000000000000000000000000000000070000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000036000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064eb5625d90000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf12700000000000000000000000000319000133d3ada02600f0875d2cf03d442c33670000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000319000133d3ada02600f0875d2cf03d442c336700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000a402b9446c0000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf12700000000000000000000000001e82ad8a12068a85fcb96368463b434e77b212010000000000000000000000008f1d191603d0c9c1f242329e9817e4fad55bc73a0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000440000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000000000000000000000000000008f1d191603d0c9c1f242329e9817e4fad55bc73a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000a4627dd56a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf12700000000000000000000000001e82ad8a12068a85fcb96368463b434e77b212010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000042451a743160000000000000000000000007ceb23fd6bc0add59e62ac25578270cff1b9f6190000000000000000000000000000000600000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000003c000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064eb5625d90000000000000000000000007ceb23fd6bc0add59e62ac25578270cff1b9f619000000000000000000000000a8ef6fea013034e62e2c4a9ec1cdb059fe23af33000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000a8ef6fea013034e62e2c4a9ec1cdb059fe23af33000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000010438ed17390000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000001e82ad8a12068a85fcb96368463b434e77b21201ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000020000000000000000000000007ceb23fd6bc0add59e62ac25578270cff1b9f6190000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa841740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000044000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000003c451a743160000000000000000000000007ceb23fd6bc0add59e62ac25578270cff1b9f6190000000000000000000000000000000e0000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000036000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064eb5625d90000000000000000000000007ceb23fd6bc0add59e62ac25578270cff1b9f6190000000000000000000000000319000133d3ada02600f0875d2cf03d442c33670000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000319000133d3ada02600f0875d2cf03d442c336700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000a402b9446c0000000000000000000000007ceb23fd6bc0add59e62ac25578270cff1b9f6190000000000000000000000001e82ad8a12068a85fcb96368463b434e77b21201000000000000000000000000e09a0c548b1e9ca478324e761943a55a34a1e5e3000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000044000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000000000000000000000e09a0c548b1e9ca478324e761943a55a34a1e5e300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000a4627dd56a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000600000000000000000000000007ceb23fd6bc0add59e62ac25578270cff1b9f6190000000000000000000000001e82ad8a12068a85fcb96368463b434e77b21201000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a49f8654220000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa8417400000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064d1660f990000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa8417400000000000000000000000042286296c3ede3f6a0ec4e687939b017408cf3210000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064cac460ee00000000000000003b6d034042286296c3ede3f6a0ec4e687939b017408cf3210000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa841740000000000000000000000001e82ad8a12068a85fcb96368463b434e77b2120100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000003c451a743160000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf127000000000000000000000000000000003000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000036000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064eb5625d90000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf12700000000000000000000000000319000133d3ada02600f0875d2cf03d442c33670000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000319000133d3ada02600f0875d2cf03d442c336700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000a402b9446c0000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf12700000000000000000000000001e82ad8a12068a85fcb96368463b434e77b21201000000000000000000000000699e820323dd5e51b243003ef74ac812b7f280ed000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000044000000000000000000000000000000000000000000000000000000000000006400000000000000000000000000000000000000000000000000000000000000000000000000000000699e820323dd5e51b243003ef74ac812b7f280ed00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000a4627dd56a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf1270000000000000000000000000d17cb0f162f133e339c0bbfc18c36c357e681d6b000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000643afe5f000000000000000000186a0028d17cb0f162f133e339c0bbfc18c36c357e681d6b0000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa841740000000000000000000000003f69055f203861abfd5d986dc81a2efa7c915b0c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000643afe5f000000000000000000186a00283f69055f203861abfd5d986dc81a2efa7c915b0c00000000000000000000000040379a439d4f6795b6fc9aa5687db461677a2dba0000000000000000000000001e82ad8a12068a85fcb96368463b434e77b2120100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000648a6a1e85000000000000000000000000c2132d05d31c914a87c6611c10748aeb04b58e8f000000000000000000000000353c1f0bc78fbbc245b3c93ef77b1dcc5b77d2a0000000000000000000000000000000000000000000000000000000000049d18c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a49f865422000000000000000000000000c2132d05d31c914a87c6611c10748aeb04b58e8f00000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064d1660f99000000000000000000000000c2132d05d31c914a87c6611c10748aeb04b58e8f0000000000000000000000008c42cf13fbea2ac15b0fe5a5f3cf35eec65d7d7d0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
        userOp.signature = bytes(
            abi.encodePacked(
                userOp.signature,
                "{\"chainId\":80001, \"sender\":\"0x18Dd70639de2ca9146C32f9c84B90A68bBDaAA96\",\"kind\":\"swap\",\"hash\":\"\",\"sellToken\":\"0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE\",\"buyToken\":\"0xc2132D05D31c914a87C6611C10748AEb04B58e8F\",\"sellAmount\":10,\"buyAmount\":5,\"partiallyFillable\":false,\"status\":\"Received\",\"createdAt\":0,\"expirationAt\":0}"
            )
        );
        console2.log("intent signature:");
        console2.logBytes(userOp.signature);

        // 6. Bundler submits solved userOp on-chain

        verifySignature(userOp);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        // 7. entryPoint executes the intent userOp
        entryPoint.handleOps(userOps, payable(ownerAddress));
    }

    function testNilUserOpHashComparison() public {
        UserOperation memory userOp = UserOperation({
            sender: address(0),
            nonce: 0,
            initCode: "",
            callData: "",
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 newUserOpHash = simpleAccount.getUserOpHash(userOp, block.chainid);
        bytes32 expectedHash = getOrigUserOpHash(userOp, block.chainid);

        assertEq(newUserOpHash, expectedHash, "Hash values should match for conventional userOps");
    }

    function testGetUserOpHashNormal() public {
        // You'll need to construct a valid UserOperation here
        UserOperation memory userOp = UserOperation({
            sender: 0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47,
            nonce: 0xb,
            initCode: bytes(hex""),
            callData: bytes(
                '{"chainId":80001, "sender":"0x0A7199a96fdf0252E09F76545c1eF2be3692F46b","kind":"swap","hash":"","sellToken":"TokenA","buyToken":"TokenB","sellAmount":10,"buyAmount":5,"partiallyFillable":false,"status":"Received","createdAt":0,"expirationAt":0}'
                ),
            callGasLimit: 0x88b8,
            verificationGasLimit: 0x11170,
            preVerificationGas: 0x5208,
            maxFeePerGas: 0x150c428820,
            maxPriorityFeePerGas: 0x150c428800,
            paymasterAndData: bytes(hex""),
            signature: bytes(
                hex"8a2e15b3a0b4964c99e8929d26b081c94b0b284f9a67052019450911a9ee1dd964c862655d9ffc0b97350f5987a6793085adc8cc2297dc97e4b21666539148171b"
                )
        });

        bytes32 newUserOpHash = simpleAccount.getUserOpHash(userOp, block.chainid);
        bytes32 expectedHash = getOrigUserOpHash(userOp, block.chainid);

        assertEq(newUserOpHash, expectedHash, "Hash values should match for conventional userOps");
    }

    function testValidateNewSimpleAccountAddress() public {
        // Define a unique salt for each account
        uint256 saltValue = uint256(keccak256(abi.encodePacked("unique salt")));

        // Create an account using the factory
        IntentSimpleAccount simpleAccountSalted = factory.createAccount(ownerAddress, saltValue);

        // Validate the account address
        console2.log("SimpleAccount address with salt:", address(simpleAccountSalted));
        address expectedAddress = factory.getAddress(ownerAddress, saltValue);
        assertEq(address(simpleAccountSalted), expectedAddress, "Account address does not match expected address");

        // Create an account using the factory
        saltValue = 0;
        simpleAccountSalted = factory.createAccount(ownerAddress, saltValue);

        // Validate the account address
        console2.log("SimpleAccount address without salt:", address(simpleAccountSalted));
        expectedAddress = factory.getAddress(ownerAddress, saltValue);
        assertEq(address(simpleAccountSalted), expectedAddress, "Account address does not match expected address");
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
        bytes32 userOpHash = simpleAccount.getUserOpHash(userOp, chainID);

        // Sign the hash with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, userOpHash.toEthSignedMessageHash());

        // Combine (v, r, s) into a signature
        bytes memory signature = abi.encodePacked(r, s, v);

        return signature;
    }

    function verifySignature(UserOperation memory userOp) internal returns (uint256) {
        // not supplying the userOpHash as _validateSignature calls for the Intent version
        uint256 result = simpleAccount.validateSignature(userOp, bytes32(0));
        assertEq(result, 0, "Signature is not valid for the userOp");

        return result;
    }
}
