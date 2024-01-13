// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "../src/SimpleAccount.sol";
import "../src/IEntryPoint.sol";
import "../src/EntryPoint.sol";
import "../src/SimpleAccountFactory.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

using Strings for bytes32;
using UserOperationLib for UserOperation;

contract SimpleAccountTest is Test {
    address public constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    uint256 public constant MUMBAI_CHAIN_ID = 80001;
    uint256 mumbaiFork;

    using ECDSA for bytes32;

    SimpleAccountFactory public factory;
    SimpleAccount simpleAccount;
    uint256 salt = 0;
    IEntryPoint public entryPoint;
    address public ownerAddress;
    uint256 public ownerPrivateKey;
    IERC20 public token;

    function setUp() public {
        // Retrieve the MUMBAI_PRIVATE_KEY from the .env file
        string memory mumbaiPrivateKeyString = vm.envString("MUMBAI_PRIVATE_KEY");

        // Derive the Ethereum address from the private key
        ownerPrivateKey = vm.parseUint(mumbaiPrivateKeyString);
        ownerAddress = vm.addr(ownerPrivateKey);
        assertEq(ownerAddress, 0xa4BFe126D3aD137F972695dDdb1780a29065e556, "Owner address should match");

        // Create a VM instance for the MUMBAI fork
        mumbaiFork = vm.createSelectFork(vm.envString("MUMBAI_RPC_URL"));
        assertEq(MUMBAI_CHAIN_ID, block.chainid, "chainid should be 80001");

        vm.startPrank(ownerAddress);

        // Deploy the EntryPoint contract or use an existing one
        entryPoint = EntryPoint(payable(ENTRYPOINT_V06));
        console2.log("EntryPoint deployed at:", address(entryPoint));

        // Deploy the SimpleAccountFactory with the entry point
        factory = new SimpleAccountFactory(entryPoint);

        // Create an account using the factory
        simpleAccount = factory.createAccount(ownerAddress, salt);
        console2.log("SimpleAccount deployed at:", address(simpleAccount));
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

    function testValidateSignature() public {
        // Validate the account address
        address expectedAddress = factory.getAddress(ownerAddress, salt);
        assertEq(address(simpleAccount), expectedAddress, "Account address does not match expected address");

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
        uint256 result = simpleAccount.ValidateSignature(userOp, bytes32(0));
        assertEq(result, 0, "Signature should be valid");
    }

    function testValidateMumbaiVanillaOp() public {
        assertEq(block.chainid, MUMBAI_CHAIN_ID, "chainid should be 80001");

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

        // Generate the signature
        string memory generatedSignatureHex = toHexString(generateSignature(userOp, block.chainid));

        verifySignature(
            userOp,
            generatedSignatureHex,
            "0x92f25342760a82b7e5649ed7c6d2d7cb93c0093f66c916d7e57de4af0ae00e2b0524bf364778c6b30c491354be332a1ce521e8a57c5e26f94f8069a404520e931b"
        );
    }

    function testValidateMumbaiLongCallData() public {
        assertEq(block.chainid, MUMBAI_CHAIN_ID, "chainid should be 80001");

        // Prepare the UserOperation object to sign
        UserOperation memory userOp = UserOperation({
            sender: 0x6B5f6558CB8B3C8Fec2DA0B1edA9b9d5C064ca47,
            nonce: 0xb,
            initCode: bytes(hex""),
            callData: bytes(
                hex"c7cd97480000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000012000000000000000000000000066c0aee289c4d332302dda4ded0c0cdc3784939a0000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000053a3e3f4800000000000000000000000067297ee4eb097e072b4ab6f1620268061ae804640000000000000000000000002397d2fde31c5704b02ac1ec9b770f23d70d8ec4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000149000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006352a56caadc4f1e25cd6c75970fa768a3304e6466c0aee289c4d332302dda4ded0c0cdc3784939a562e362876c8aee4744fc2c6aac8394c312d215d1f9840a85d5af5bf1d1762f925bdaddc4201f9840000000000000000000000000000000000000000000000000000000439689a920000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000006596a37066c0aee289c4d332302dda4ded0c0cdc3784939a1dfa0ff0b2e64429acf334d64097b28000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004109ffe4bb46d80a7da156ae6795558927a3613cc6073ddad94296335191660e673c7696803900ccd4b4ba1012a198259f0ce8c3873247ce209a326185458cede61c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000a0490411a32000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000001f9840a85d5af5bf1d1762f925bdaddc4201f984000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d000000000000000000000000dafd66636e2561b0284edde37e42d192f2844d40000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a760000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000439689a930000000000000000000000000000000000000000000000000000000547c2c13700000000000000000000000000000000000000000000000000000000000000020000000000000000000000008ba3c3f7334375f95c128bc6a9b8fc42e870f160000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000004a000000000000000000000000000000000000000000000000000000000000005c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064cac460ee00000000000000003b6d0340dafd66636e2561b0284edde37e42d192f2844d400000000000000000000000001f9840a85d5af5bf1d1762f925bdaddc4201f984000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000002449f865422000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc200000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000104e5b07cdb0000000000000000000000004e4abd1c111c08b3a05feed46556496e6a3fd89300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000a9c0cded336699547aac4f9de5a11ada979bc59a00000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000002ec02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000bb8562e362876c8aee4744fc2c6aac8394c312d215d0000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000648a6a1e85000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d000000000000000000000000353c1f0bc78fbbc245b3c93ef77b1dcc5b77d2a00000000000000000000000000000000000000000000000000000000547c2c13700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a49f865422000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d00000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000064d1660f99000000000000000000000000562e362876c8aee4744fc2c6aac8394c312d215d000000000000000000000000ead050515e10fdb3540ccd6f8236c46790508a760000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
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

        // Generate the signature
        string memory generatedSignatureHex = toHexString(generateSignature(userOp, block.chainid));

        verifySignature(
            userOp,
            generatedSignatureHex,
            "0x74199499de42614e0172afc5781179682f311ed1ec8b369d5a4d8bae4e68f3387e9cab11473b4fb65932e4a8812793f6b7e80a9700855fde454109ceeac02e911b"
        );
    }

    function testValidateMumbai_UnsolvedIntentOp() public {
        assertEq(block.chainid, MUMBAI_CHAIN_ID, "chainid should be 80001");

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

        // Generate the signature
        string memory generatedSignatureHex = toHexString(generateSignature(userOp, block.chainid));

        verifySignature(
            userOp,
            generatedSignatureHex,
            "0x8a2e15b3a0b4964c99e8929d26b081c94b0b284f9a67052019450911a9ee1dd964c862655d9ffc0b97350f5987a6793085adc8cc2297dc97e4b21666539148171b"
        );
    }

    function testValidateMumbai_UnsolvedIntent0GasOp() public {
        assertEq(block.chainid, MUMBAI_CHAIN_ID, "chainid should be 80001");

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

        // Generate the signature
        string memory generatedSignatureHex = toHexString(generateSignature(userOp, block.chainid));

        verifySignature(
            userOp,
            generatedSignatureHex,
            "0x1b2c01e59028d70e881fc913570014ca4d693e29725dbbb5cd56cdc8b8f5007e6188fd6afd3482d65703c3a884195712c901aebf3a0964de04367e8c827340db1b"
        );
    }

    function testValidateMumbai_SolvedNilIntentOp() public {
        assertEq(block.chainid, MUMBAI_CHAIN_ID, "chainid should be 80001");

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

        // Generate the signature
        string memory generatedSignatureHex = toHexString(generateSignature(userOp, block.chainid));

        verifySignature(
            userOp,
            generatedSignatureHex,
            "0x1b81c8280ec9fbf3009c650a67eadac8ab53ab645f55bdb927a870b40649904f7d1a5e9bd75b7e362625f05874f53d9e071cdc27baa43fc5a89b1338f24a9c7b1b"
        );
    }

    function testValidateMumbai_SolvedIntentOpNilSolution() public {
        assertEq(block.chainid, MUMBAI_CHAIN_ID, "chainid should be 80001");

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

        // Generate the signature
        string memory generatedSignatureHex = toHexString(generateSignature(userOp, block.chainid));

        verifySignature(
            userOp,
            generatedSignatureHex,
            "0xe14ea21c8d6478388bfc9e5f1bf9a0d45fe1359fbfeac193e8b504be2db9fc317f6c6b06bff42328af64f6be85a31e729d2cab6c6b83ebf3ef12bc4cc344e9c31c"
        );
    }

    function testValidateMumbai_SolvedIntentOp() public {
        assertEq(block.chainid, MUMBAI_CHAIN_ID, "chainid should be 80001");

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

        // Generate the signature
        string memory generatedSignatureHex = toHexString(generateSignature(userOp, block.chainid));

        verifySignature(
            userOp,
            generatedSignatureHex,
            "0x1b2c01e59028d70e881fc913570014ca4d693e29725dbbb5cd56cdc8b8f5007e6188fd6afd3482d65703c3a884195712c901aebf3a0964de04367e8c827340db1b"
        );
    }

    function testExecuteMumbai_EmptyOp() public {
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

    function testExecuteMumbai_vanillaUserOp() public {
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

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;
        entryPoint.handleOps(userOps, payable(ownerAddress));

        showBalances(ownerAddress, "After userOp execution");
        showBalances(address(simpleAccount), "After userOp execution");
    }

    function testValidateExecuteMumbai_SolvedOpReverted() public {
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

        // Generate the signature
        userOp.signature = generateSignature(userOp, block.chainid);

        vm.stopPrank();
        vm.prank(ENTRYPOINT_V06);
        simpleAccount.validateUserOp(userOp, bytes32(0), 0);
        vm.startPrank(ownerAddress);
        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;
        bytes32 userOpHash = getOrigUserOpHash(userOp, block.chainid);
        vm.expectEmit(true, true, true, true);
        
        // successful request with ** reverted sender transaction **
        emit IEntryPoint.UserOperationEvent(
            userOpHash, userOp.sender, address(0), uint256(0), false, uint256(0), uint256(476954)
        );
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

    function testFindIntentEndIndexWithToken127BytesMockPrefix() public {
        bytes memory mockPayload = new bytes(127); // Create a mock payload of 127 bytes
        bytes memory data = abi.encodePacked(mockPayload, hex"7B696E74656E74206A736F6E7D3C696E74656E742D656E643E3078"); // "{intent json}<intent-end>0x"
        int256 index = simpleAccount.findIntentEndIndex(data);
        assertEq(index, int256(127 + 13), "Incorrect index for <intent-end> with 127-byte mock prefix");
    }

    function testFindIntentEndIndexWithTokenMoreThan128BytesMockPrefix() public {
        bytes memory mockPayload = new bytes(129); // Create a mock payload of 129 bytes
        bytes memory data = abi.encodePacked(mockPayload, hex"7B696E74656E74206A736F6E7D3C696E74656E742D656E643E3078"); // "{intent json}<intent-end>0x"
        int256 index = simpleAccount.findIntentEndIndex(data);
        assertEq(index, int256(129 + 13), "Incorrect index for <intent-end> with more than 128-byte mock prefix");
    }

    function testFindIntentEndIndexWithoutToken127BytesMockPrefix() public {
        bytes memory mockPayload = new bytes(127); // Create a mock payload of 127 bytes
        bytes memory data = abi.encodePacked(mockPayload, "No token here");
        int256 index = simpleAccount.findIntentEndIndex(data);
        assertEq(index, -1, "Index should be -1 when token is absent with 127-byte mock prefix");
    }

    function testFindIntentEndIndexWithoutTokenMoreThan128BytesMockPrefix() public {
        bytes memory mockPayload = new bytes(129); // Create a mock payload of 129 bytes
        bytes memory data = abi.encodePacked(mockPayload, "No token here");
        int256 index = simpleAccount.findIntentEndIndex(data);
        assertEq(index, -1, "Index should be -1 when token is absent with more than 128-byte mock prefix");
    }

    function testFindIntentEndIndexWithToken() public {
        bytes memory data = bytes("{intent json}<intent-end>0x");
        int256 index = simpleAccount.findIntentEndIndex(data);
        assertEq(index, int256(13), "Incorrect index for <intent-end>");
    }

    function testFindIntentEndIndexWithoutToken() public {
        bytes memory data = bytes("No token here");
        int256 index = simpleAccount.findIntentEndIndex(data);
        assertEq(index, -1, "Index should be -1 when token is absent");
    }

    function testFindIntentEndIndexEmptyData() public {
        bytes memory data = "";
        int256 index = simpleAccount.findIntentEndIndex(data);
        assertEq(index, -1, "Index should be -1 for empty data");
    }

    function testSliceNormal() public {
        bytes memory data = bytes("Intents Rock");
        bytes memory result = simpleAccount.slice(data, 0, 7);
        assertEq(string(result), "Intents", "Slicing did not return the correct result");
    }

    function testSliceOutOfBounds() public {
        bytes memory data = bytes("Intents Are Nice.");
        try simpleAccount.slice(data, 0, 50) {
            fail("slice should have thrown for end out of bounds");
        } catch (bytes memory) {
            // expected
        }
    }

    function testSliceStartOutOfBounds() public {
        bytes memory data = bytes("Intents Are Nice.");
        try simpleAccount.slice(data, 50, 60) {
            fail("slice should have thrown for start out of bounds");
        } catch (bytes memory) {
            // expected
        }
    }

    function testSliceEndLessThanStart() public {
        bytes memory data = bytes("Intents Are In!");
        try simpleAccount.slice(data, 5, 2) {
            fail("slice should have thrown for end less than start");
        } catch (bytes memory) {
            // expected
        }
    }

    function testValidateNewSimpleAccountAddress() public {
        // Define a unique salt for each account
        uint256 saltValue = uint256(keccak256(abi.encodePacked("unique salt")));

        // Create an account using the factory
        SimpleAccount simpleAccountSalted = factory.createAccount(ownerAddress, saltValue);

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

    function verifySignature(
        UserOperation memory userOp,
        string memory generatedSignatureHex,
        string memory userOpSignatureHex
    ) internal returns (uint256) {
        assertEq(generatedSignatureHex, userOpSignatureHex, "Signatures should match");

        // not supplying the userOpHash as _validateSignature calls for the Intent version
        uint256 result = simpleAccount.ValidateSignature(userOp, bytes32(0));
        assertEq(result, 0, "Signature is not valid for the userOp");

        return result;
    }
}
