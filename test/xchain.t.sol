// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "./TestSimpleAccountHelper.sol";

contract XChainLibTest is Test {
    using XChainLib for bytes;

    function extractCallData(bytes calldata callData) public pure returns (bytes calldata) {
        return XChainLib.extractCallData(callData);
    }

    function testEncodeAndDecodeXChainCallData() public {
        bytes32 otherChainHash = keccak256("deadbeef");
        bytes[] memory ops = new bytes[](2);
        ops[0] = TestSimpleAccountHelper.createCrossChainCallData(hex"deadbeef", otherChainHash);
        ops[1] = TestSimpleAccountHelper.createCrossChainCallData(hex"cafebabe", otherChainHash);

        assertEq(this.extractCallData(ops[0]), hex"deadbeef");
        assertEq(this.extractCallData(ops[1]), hex"cafebabe");
    }

    function testIdentifyUserOpType() public {
        // Test Conventional UserOp
        assertEq(
            uint256(XChainLib.identifyUserOpType(hex"")),
            uint256(XChainLib.OpType.Conventional),
            "Empty calldata should be Conventional"
        );
        assertEq(
            uint256(XChainLib.identifyUserOpType(hex"00deadbeef")),
            uint256(XChainLib.OpType.Conventional),
            "Conventional UserOp should be identified"
        );
        assertEq(
            uint256(XChainLib.identifyUserOpType(hex"03deadbeef")),
            uint256(XChainLib.OpType.Conventional),
            "Invalid opType should be Conventional"
        );

        bytes32 dummyHash = bytes32(uint256(0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0));

        // Test SourceUserOp
        bytes memory sourceUserOp = abi.encodePacked(
            uint16(XChainLib.XC_MARKER), // opType for cross-chain
            uint16(8), // src-calldata-length
            hex"1234567890abcdef", // src-calldata-value
            dummyHash
        );
        assertEq(
            uint256(XChainLib.identifyUserOpType(sourceUserOp)),
            uint256(XChainLib.OpType.CrossChain),
            "Should be identified as SourceUserOp"
        );

        // Test DestUserOp
        bytes32 dummyHash1 = bytes32(uint256(0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0));
        bytes memory destUserOp = abi.encodePacked(
            uint16(XChainLib.XC_MARKER), // opType for cross-chain
            uint16(4), // dest-calldata-length
            hex"deadbeef", // dest-calldata-value
            dummyHash1 // hash1
        );
        assertEq(
            uint256(XChainLib.identifyUserOpType(destUserOp)),
            uint256(XChainLib.OpType.CrossChain),
            "Should be identified as DestUserOp"
        );

        // Test invalid cases (should return Conventional)
        assertEq(
            uint256(XChainLib.identifyUserOpType(hex"0100")),
            uint256(XChainLib.OpType.Conventional),
            "Incomplete SourceUserOp should be Conventional"
        );
        assertEq(
            uint256(XChainLib.identifyUserOpType(hex"0200")),
            uint256(XChainLib.OpType.Conventional),
            "Incomplete DestUserOp should be Conventional"
        );

        // Test edge cases
        bytes memory edgeCaseSource = abi.encodePacked(
            uint8(1), // opType for SourceUserOp
            uint16(4), // src-calldata-length
            hex"deadbeef" // src-calldata-value
                // missing dest-userOp-encoded
        );
        assertEq(
            uint256(XChainLib.identifyUserOpType(edgeCaseSource)),
            uint256(XChainLib.OpType.Conventional),
            "Invalid SourceUserOp structure should be Conventional"
        );

        bytes memory edgeCaseDest = abi.encodePacked(
            uint8(2), // opType for DestUserOp
            uint16(4), // dest-calldata-length
            hex"deadbeef", // dest-calldata-value
            bytes31(0) // incomplete hash1
        );
        assertEq(
            uint256(XChainLib.identifyUserOpType(edgeCaseDest)),
            uint256(XChainLib.OpType.Conventional),
            "Invalid DestUserOp structure should be Conventional"
        );
    }

    /**
     * @dev Test the gas cost of extracting cross-chain call data.
     * This function performs the following:
     * 1. Creates a SourceUserOp with embedded DestUserOp.
     * 2. Measures the gas cost of identifying the UserOp type.
     * 3. Measures the gas cost of extracting the source call data.
     * 4. Measures the gas cost of extracting the destination call data.
     */
    function testExtractXChainCallDataGasCost() public {
        // Create a SourceUserOp with embedded DestUserOp
        bytes memory srcCallData = new bytes(1000); // Source call data of 1000 bytes
        bytes memory destCallData = new bytes(2000); // Destination call data of 2000 bytes
        bytes32 dummyHash1 = bytes32(uint256(0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0));

        // Create cross-chain call data for source and destination
        bytes memory sourceUserOpCallData = TestSimpleAccountHelper.createCrossChainCallData(srcCallData, dummyHash1);
        bytes memory destUserOpEncoded = TestSimpleAccountHelper.createCrossChainCallData(destCallData, dummyHash1);

        // Measure gas cost for identifying UserOp type
        uint256 gasStart = gasleft();
        XChainLib.OpType opType = XChainLib.identifyUserOpType(sourceUserOpCallData);
        bool isXChainCallData = opType == XChainLib.OpType.CrossChain;
        assertEq(isXChainCallData, true, "Should be identified as SourceUserOp");
        uint256 gasUsed = gasStart - gasleft();
        console2.log("Gas used for identifyUserOpType:", gasUsed);

        // Measure gas cost for extracting source call data
        gasStart = gasleft();
        bytes memory extractedSrcCallData = this.extractCallData(sourceUserOpCallData);
        gasUsed = gasStart - gasleft();
        assertEq(extractedSrcCallData, srcCallData, "Extracted source callData should match");
        console2.log("Gas used for extractSourceUserOpData:", gasUsed);

        // Measure gas cost for extracting destination call data
        gasStart = gasleft();
        bytes memory extractedDestCallData = this.extractCallData(destUserOpEncoded);
        gasUsed = gasStart - gasleft();
        assertEq(extractedDestCallData, destCallData, "Extracted destination callData should match");
        console2.log("Gas used for extractDestUserOpData:", gasUsed);
    }
}
