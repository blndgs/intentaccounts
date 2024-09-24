// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import "./TestSimpleAccountHelper.sol";

contract XChainLibTest is Test {
    using XChainLib for bytes;

    function extractCallDataAndHashList(bytes calldata callData)
        public
        pure
        returns (bytes32 callDataHash, bytes32[3] memory hashList, uint256 listCount)
    {
        return XChainLib.extractCallDataAndHashList(callData);
    }

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

        (bytes32 cdHash, bytes32[3] memory hashList, uint256 listCount) = this.extractCallDataAndHashList(ops[0]);
        assertEq(listCount, 2, "Hash list length should be 2");
        assertEq(cdHash, keccak256(hex"deadbeef"), "Calldata Hash should match");

        // Check hash list entries
        assertEq(hashList[0], bytes32(uint256(0xFFFF) << 240), "First hash should be placeholder");
        assertEq(hashList[1], otherChainHash, "Second hash should be otherChainHash");

        (cdHash, hashList, listCount) = this.extractCallDataAndHashList(ops[1]);
        assertEq(listCount, 2, "Hash list length should be 2");
        assertEq(cdHash, keccak256(hex"cafebabe"), "Calldata Hash should match");

        // Check hash list entries
        assertEq(hashList[0], otherChainHash, "First hash should be otherChainHash");
        assertEq(hashList[1], bytes32(uint256(0xFFFF) << 240), "Second hash should be placeholder");
    }

    // function testIdentifyUserOpType() public {
    //     // Test Conventional UserOp
    //     assertEq(
    //         uint256(XChainLib.identifyUserOpType(hex"")),
    //         uint256(XChainLib.OpType.Conventional),
    //         "Empty calldata should be Conventional"
    //     );
    //     assertEq(
    //         uint256(XChainLib.identifyUserOpType(hex"00deadbeef")),
    //         uint256(XChainLib.OpType.Conventional),
    //         "Conventional UserOp should be identified"
    //     );
    //     assertEq(
    //         uint256(XChainLib.identifyUserOpType(hex"03deadbeef")),
    //         uint256(XChainLib.OpType.Conventional),
    //         "Invalid opType should be Conventional"
    //     );

    //     bytes32 dummyHash = bytes32(uint256(0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0));

    //     // Test SourceUserOp
    //     bytes memory sourceUserOp = abi.encodePacked(
    //         uint16(XChainLib.XC_MARKER), // opType for cross-chain
    //         uint16(8), // src-calldata-length
    //         hex"1234567890abcdef", // src-calldata-value
    //         dummyHash
    //     );
    //     assertEq(
    //         uint256(XChainLib.identifyUserOpType(sourceUserOp)),
    //         uint256(XChainLib.OpType.CrossChain),
    //         "Should be identified as SourceUserOp"
    //     );

    //     // Test DestUserOp
    //     bytes32 dummyHash1 = bytes32(uint256(0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0));
    //     bytes memory destUserOp = abi.encodePacked(
    //         uint16(XChainLib.XC_MARKER), // opType for cross-chain
    //         uint16(4), // dest-calldata-length
    //         hex"deadbeef", // dest-calldata-value
    //         dummyHash1 // hash1
    //     );
    //     assertEq(
    //         uint256(XChainLib.identifyUserOpType(destUserOp)),
    //         uint256(XChainLib.OpType.CrossChain),
    //         "Should be identified as DestUserOp"
    //     );

    //     // Test invalid cases (should return Conventional)
    //     assertEq(
    //         uint256(XChainLib.identifyUserOpType(hex"0100")),
    //         uint256(XChainLib.OpType.Conventional),
    //         "Incomplete SourceUserOp should be Conventional"
    //     );
    //     assertEq(
    //         uint256(XChainLib.identifyUserOpType(hex"0200")),
    //         uint256(XChainLib.OpType.Conventional),
    //         "Incomplete DestUserOp should be Conventional"
    //     );

    //     // Test edge cases
    //     bytes memory edgeCaseSource = abi.encodePacked(
    //         uint8(1), // opType for SourceUserOp
    //         uint16(4), // src-calldata-length
    //         hex"deadbeef" // src-calldata-value
    //             // missing dest-userOp-encoded
    //     );
    //     assertEq(
    //         uint256(XChainLib.identifyUserOpType(edgeCaseSource)),
    //         uint256(XChainLib.OpType.Conventional),
    //         "Invalid SourceUserOp structure should be Conventional"
    //     );

    //     bytes memory edgeCaseDest = abi.encodePacked(
    //         uint8(2), // opType for DestUserOp
    //         uint16(4), // dest-calldata-length
    //         hex"deadbeef", // dest-calldata-value
    //         bytes31(0) // incomplete hash1
    //     );
    //     assertEq(
    //         uint256(XChainLib.identifyUserOpType(edgeCaseDest)),
    //         uint256(XChainLib.OpType.Conventional),
    //         "Invalid DestUserOp structure should be Conventional"
    //     );
    // }

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
        // XChainLib.OpType opType = XChainLib.identifyUserOpType(sourceUserOpCallData);
        // bool isXChainCallData = opType == XChainLib.OpType.CrossChain;
        // assertEq(isXChainCallData, true, "Should be identified as cross-chain");
        uint256 gasUsed = gasStart - gasleft();
        // console2.log("Gas used for identifyUserOpType:", gasUsed);

        // Measure gas cost for extracting source call data
        gasStart = gasleft();
        (bytes32 cdHash, bytes32[3] memory hashList, uint256 listCount) =
            this.extractCallDataAndHashList(sourceUserOpCallData);
        gasUsed = gasStart - gasleft();
        console2.log("Gas used for extractSourceUserOpData:", gasUsed);

        assertEq(listCount, 2, "hashlist length should match");
        assertEq(cdHash, keccak256(srcCallData), "Extracted source callData should match");

        // Check hash list entries
        assertEq(hashList[0], bytes32(uint256(0xFFFF) << 240), "First hash should be placeholder");
        assertEq(hashList[1], dummyHash1, "Second hash should be otherChainHash");

        // Measure gas cost for extracting destination call data
        gasStart = gasleft();
        (cdHash, hashList, listCount) = this.extractCallDataAndHashList(destUserOpEncoded);
        gasUsed = gasStart - gasleft();
        console2.log("Gas used for extractDestUserOpData:", gasUsed);
        assertEq(listCount, 2, "Hash list length should be 2");
        assertEq(cdHash, keccak256(destCallData), "Calldata Hash should match");

        // Check hash list entries
        assertEq(hashList[0], dummyHash1, "First hash should be otherChainHash");
        assertEq(hashList[1], bytes32(uint256(0xFFFF) << 240), "Second hash should be placeholder");
    }
}
