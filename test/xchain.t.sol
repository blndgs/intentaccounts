// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "./TestSimpleAccountHelper.sol";

contract XChainLibTest is Test {
    using XChainLib for bytes;

    function testEncodeAndDecodeXChainCallData() public {
        // Placeholder as 2 bytes
        bytes memory placeholder = abi.encodePacked(uint16(0xFFFF));
        bytes32 otherChainHash = keccak256("deadbeef");

        // Build the hash lists
        // define a bytes slice of length 2
        bytes[] memory srcHashList = new bytes[](2);
        bytes[] memory destHashList = new bytes[](2);
        srcHashList[0] = placeholder; // Placeholder in position 0
        srcHashList[1] = abi.encodePacked(otherChainHash);

        destHashList[0] = abi.encodePacked(otherChainHash);
        destHashList[1] = placeholder; // Placeholder in position 1

        bytes[] memory ops = new bytes[](2);
        ops[0] = TestSimpleAccountHelper.createCrossChainCallData(hex"deadbeef", srcHashList);
        ops[1] = TestSimpleAccountHelper.createCrossChainCallData(hex"cafebabe", destHashList);

        // (bytes32 cdHash, bytes32[3] memory hashList, uint256 listCount) = this.extractCallDataAndHashList(ops[0]);
        XChainLib.xCallData memory xcd = this.parseXElems(ops[0]);
        assertEq(xcd.hashCount, 2, "Hash list length should be 2");
        assertEq(xcd.callDataHash, keccak256(hex"deadbeef"), "Calldata Hash should match");

        // Check hash list entries
        assertEq(xcd.hashList[0], bytes32(uint256(0xFFFF) << 240), "First hash should be placeholder");
        assertEq(xcd.hashList[1], otherChainHash, "Second hash should be otherChainHash");

        // (cdHash, xcd.hashList, listCount) = this.extractCallDataAndHashList(ops[1]);
        xcd = this.parseXElems(ops[1]);
        assertEq(xcd.hashCount, 2, "Hash list length should be 2");
        assertEq(xcd.callDataHash, keccak256(hex"cafebabe"), "Calldata Hash should match");

        // Check hash list entries
        assertEq(xcd.hashList[0], otherChainHash, "First hash should be otherChainHash");
        assertEq(xcd.hashList[1], bytes32(uint256(0xFFFF) << 240), "Second hash should be placeholder");
    }

    function parseXElems(bytes calldata callData) external pure returns (XChainLib.xCallData memory) {
        return XChainLib.parseXElems(callData);
    }

    function testIdentifyUserOpType() public {
        // Test Conventional UserOp
        XChainLib.xCallData memory xcd = this.parseXElems(hex"");
        assertEq(uint256(xcd.opType), uint256(XChainLib.OpType.Conventional), "Empty calldata should be Conventional");
        xcd = this.parseXElems(hex"00deadbeef");
        assertEq(
            uint256(xcd.opType), uint256(XChainLib.OpType.Conventional), "Conventional UserOp should be identified"
        );
        xcd = this.parseXElems(hex"03deadbeef");
        assertEq(uint256(xcd.opType), uint256(XChainLib.OpType.Conventional), "Invalid opType should be Conventional");

        bytes32 dummyHash = bytes32(uint256(0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0));

        bytes memory placeholder = abi.encodePacked(uint16(XChainLib.XC_MARKER));
        bytes[] memory srcHashList = new bytes[](2);
        srcHashList[0] = placeholder; // Placeholder in position 0 for source userOp hash1
        srcHashList[1] = abi.encodePacked(dummyHash);

        // Test SourceUserOp
        bytes memory sourceUserOp = TestSimpleAccountHelper.createCrossChainCallData(hex"1234567890abcdef", srcHashList);
        xcd = this.parseXElems(sourceUserOp);
        assertEq(
            uint256(xcd.opType),
            uint256(XChainLib.OpType.CrossChain),
            "sourceUserOp should be identified as cross-chain opType"
        );

        // Test DestUserOp
        bytes32 dummyHash1 = bytes32(uint256(0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0));
        bytes[] memory destHashList = new bytes[](2);
        destHashList[0] = abi.encodePacked(dummyHash1);
        destHashList[1] = placeholder; // Placeholder in position 1 for destination chain userOp hash2
        bytes memory destUserOp = TestSimpleAccountHelper.createCrossChainCallData(hex"deadbeef", destHashList);
        xcd = this.parseXElems(destUserOp);
        assertEq(
            uint256(xcd.opType),
            uint256(XChainLib.OpType.CrossChain),
            "DestUserOp should be identified as crosschain opType"
        );

        // Test invalid cases (should return Conventional)
        xcd = this.parseXElems(hex"0100");
        assertEq(
            uint256(xcd.opType),
            uint256(XChainLib.OpType.Conventional),
            "Incomplete SourceUserOp should be Conventional"
        );
        xcd = this.parseXElems(hex"0200");
        assertEq(
            uint256(xcd.opType), uint256(XChainLib.OpType.Conventional), "Incomplete DestUserOp should be Conventional"
        );

        // Test edge cases
        bytes memory edgeCaseSource = abi.encodePacked(
            uint8(1), // opType for SourceUserOp
            uint16(4), // src-calldata-length
            hex"deadbeef" // src-calldata-value
                // missing dest-userOp-encoded
        );
        xcd = this.parseXElems(edgeCaseSource);
        assertEq(
            uint256(xcd.opType),
            uint256(XChainLib.OpType.Conventional),
            "Invalid SourceUserOp structure should be Conventional"
        );

        bytes memory edgeCaseDest = abi.encodePacked(
            uint8(2), // opType for DestUserOp
            uint16(4), // dest-calldata-length
            hex"deadbeef", // dest-calldata-value
            bytes31(0) // incomplete hash1
        );
        xcd = this.parseXElems(edgeCaseDest);
        assertEq(
            uint256(xcd.opType),
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

        bytes memory placeholder = abi.encodePacked(uint16(0xFFFF));

        // Build the hash lists
        // define a bytes slice of length 2
        bytes[] memory srcHashList = new bytes[](2);
        bytes[] memory destHashList = new bytes[](2);
        srcHashList[0] = placeholder; // Placeholder in position 0
        srcHashList[1] = abi.encodePacked(dummyHash1);

        destHashList[0] = abi.encodePacked(dummyHash1);
        destHashList[1] = placeholder; // Placeholder in position 1

        // Create cross-chain call data for source and destination
        bytes memory sourceUserOpCallData = TestSimpleAccountHelper.createCrossChainCallData(srcCallData, srcHashList);
        bytes memory destUserOpEncoded = TestSimpleAccountHelper.createCrossChainCallData(destCallData, destHashList);

        // Measure gas cost for identifying UserOp type
        uint256 gasStart = gasleft();
        XChainLib.xCallData memory xcd = this.parseXElems(sourceUserOpCallData);
        uint256 gasUsed = gasStart - gasleft();
        console2.log("Gas used for parseXElems:", gasUsed);
        bool isXChainCallData = xcd.opType == XChainLib.OpType.CrossChain;
        assertEq(isXChainCallData, true, "Should be identified as cross-chain");
        assertEq(xcd.hashCount, 2, "hashlist length should match");
        assertEq(xcd.callDataHash, keccak256(srcCallData), "Extracted source callData should match");

        // Check hash list entries
        assertEq(xcd.hashList[0], bytes32(uint256(0xFFFF) << 240), "First hash should be placeholder");
        assertEq(xcd.hashList[1], dummyHash1, "Second hash should be otherChainHash");

        // Measure gas cost for extracting destination call data
        gasStart = gasleft();
        xcd = this.parseXElems(destUserOpEncoded);
        gasUsed = gasStart - gasleft();
        console2.log("Gas used for extractDestUserOpData:", gasUsed);
        assertEq(xcd.hashCount, 2, "Hash list length should be 2");
        assertEq(xcd.callDataHash, keccak256(destCallData), "Calldata Hash should match");

        // Check xcd.hash list entries
        assertEq(xcd.hashList[0], dummyHash1, "First hash should be otherChainHash");
        assertEq(xcd.hashList[1], bytes32(uint256(0xFFFF) << 240), "Second hash should be placeholder");
    }
}
