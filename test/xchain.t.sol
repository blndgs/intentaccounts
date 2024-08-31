// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "./TestSimpleAccountHelper.sol";
import "../src/xchainlib.sol";

contract XChainLibTest is Test {
    using XChainLib for bytes;

    function setUp() public {}

    function testEncodeAndDecodeXChainCallData() public {
        XChainLib.xCallData[] memory ops = new XChainLib.xCallData[](3);
        ops[0] = XChainLib.xCallData(1, hex"deadbeef");
        ops[1] = XChainLib.xCallData(2, hex"cafebabe");
        ops[2] = XChainLib.xCallData(3, hex"f00dbabe");

        bytes memory encoded = TestSimpleAccountHelper.encodeXChainCallData(ops);

        assertEq(XChainLib.extractXChainCallData(encoded, 1), hex"deadbeef");
        assertEq(XChainLib.extractXChainCallData(encoded, 2), hex"cafebabe");
        assertEq(XChainLib.extractXChainCallData(encoded, 3), hex"f00dbabe");
        assertEq(XChainLib.extractXChainCallData(encoded, 4), hex"");
    }

    function testIsXChainCallData() public {
        // Test valid case
        {
            console2.log("valid case");
            XChainLib.xCallData[] memory ops = new XChainLib.xCallData[](2);
            ops[0] = XChainLib.xCallData(1, hex"deadbeef");
            ops[1] = XChainLib.xCallData(2, hex"cafebabe");
            bytes memory encoded = TestSimpleAccountHelper.encodeXChainCallData(ops);
            assertTrue(callIsXChainCallData(encoded), "Valid calldata should return true");
            console.logBytes(encoded);
        }

        // 1: calldata missing chainid value of a nested calldata
        {
            console2.log("test case 1");
            bytes memory invalidEncoded = hex"020001"; // Missing second chainId
            assertFalse(callIsXChainCallData(invalidEncoded), "Calldata missing chainId should return false");
        }

        // 2: calldata missing a number of Ops value
        {
            console2.log("test case 2");
            bytes memory invalidEncoded = hex"0001000464656164"; // Missing number of ops
            assertFalse(callIsXChainCallData(invalidEncoded), "Calldata missing number of ops should return false");
        }

        // 3: calldata missing length value of nested calldata
        {
            console2.log("test case 3");
            bytes memory invalidEncoded = hex"02000100"; // Missing length for first calldata
            assertFalse(callIsXChainCallData(invalidEncoded), "Calldata missing length should return false");
        }

        // 4: calldata with length + 1 value for a nested calldata
        {
            console2.log("test case 4");
            XChainLib.xCallData[] memory ops = new XChainLib.xCallData[](1);
            ops[0] = XChainLib.xCallData(1, hex"deadbeef");
            bytes memory encoded = TestSimpleAccountHelper.encodeXChainCallData(ops);
            console.log("Original encoded:");
            console.logBytes(encoded);

            // Create a new byte array with one extra byte
            bytes memory modifiedEncoded = new bytes(encoded.length + 1);
            for (uint256 i = 0; i < encoded.length; i++) {
                modifiedEncoded[i] = encoded[i];
            }
            // Increase the length value by 1
            modifiedEncoded[3] = bytes1(uint8(modifiedEncoded[3]) + 1);
            // Add an extra byte at the end
            modifiedEncoded[modifiedEncoded.length - 1] = 0xFF;

            console.log("Modified encoded:");
            console.logBytes(modifiedEncoded);

            bool result;
            try XChainLib.isXChainCallData(modifiedEncoded) returns (bool _result) {
                result = _result;
            } catch Error(string memory reason) {
                console.log("Error:", reason);
                result = true; // Force the test to fail
            } catch (bytes memory lowLevelData) {
                console.logBytes(lowLevelData);
                result = true; // Force the test to fail
            }
            console.log("isXChainCallData result:", result);
            assertFalse(result, "Calldata with length + 1 should return false");
        }

        // 5: calldata with length - 1 value for a nested calldata
        {
            console2.log("test case 5");
            XChainLib.xCallData[] memory ops = new XChainLib.xCallData[](1);
            ops[0] = XChainLib.xCallData(1, hex"deadbeef");
            bytes memory encoded = TestSimpleAccountHelper.encodeXChainCallData(ops);

            console2.log("Original encoded:");
            console2.logBytes(encoded);

            // Manually decrease the length value by 1
            uint16 originalLength = uint16(bytes2(abi.encodePacked(encoded[2], encoded[3])));
            console2.log("Original length:", originalLength);

            if (originalLength > 0) {
                uint16 newLength = originalLength - 1;
                encoded[2] = bytes1(uint8(newLength >> 8));
                encoded[3] = bytes1(uint8(newLength));

                console2.log("Modified encoded:");
                console2.logBytes(encoded);

                assertFalse(callIsXChainCallData(encoded), "Calldata with length - 1 should return false");
            } else {
                console2.log("Cannot decrease length: already at 0");
                // Skip this test case
            }
        }

        // 6: calldata with number of Ops value - 1
        {
            console2.log("test case 6");
            XChainLib.xCallData[] memory ops = new XChainLib.xCallData[](2);
            ops[0] = XChainLib.xCallData(1, hex"deadbeef");
            ops[1] = XChainLib.xCallData(2, hex"cafebabe");
            bytes memory encoded = TestSimpleAccountHelper.encodeXChainCallData(ops);
            // Manually decrease the number of ops by 1
            encoded[0] = bytes1(uint8(encoded[0]) - 1);
            assertFalse(callIsXChainCallData(encoded), "Calldata with number of ops - 1 should return false");
        }

        // Additional edge cases
        console2.log("test edge cases");
        assertFalse(callIsXChainCallData(new bytes(0)), "Empty calldata should return false");
        assertFalse(callIsXChainCallData(hex"deadbeef"), "Random calldata should return false");
        assertFalse(callIsXChainCallData(hex"00"), "Single byte calldata should return false");
        assertFalse(callIsXChainCallData(hex"0500010004deadbeef"), "Calldata with too many ops should return false");
    }

    function callIsXChainCallData(bytes memory data) internal pure returns (bool) {
        return XChainLib.isXChainCallData(data);
    }

    function testInvalidNumberOfOps() public {
        XChainLib.xCallData[] memory ops = new XChainLib.xCallData[](0);
        vm.expectRevert(abi.encodeWithSelector(XChainLib.InvalidNumberOfCallData.selector, 0));
        TestSimpleAccountHelper.encodeXChainCallData(ops);

        ops = new XChainLib.xCallData[](5);
        vm.expectRevert(abi.encodeWithSelector(XChainLib.InvalidNumberOfCallData.selector, 5));
        TestSimpleAccountHelper.encodeXChainCallData(ops);
    }

    function testCallDataTooLong() public {
        XChainLib.xCallData[] memory ops = new XChainLib.xCallData[](1);
        ops[0] = XChainLib.xCallData(1, new bytes(XChainLib.MAX_CALLDATA_LENGTH + 1));

        vm.expectRevert(abi.encodeWithSelector(XChainLib.CallDataTooLong.selector, XChainLib.MAX_CALLDATA_LENGTH + 1));
        TestSimpleAccountHelper.encodeXChainCallData(ops);
    }

    function testConcatChainIds() public {
        uint256 testChainId = 31337; // Assuming this is the block.chainid in the test environment

        // Test with 1 chain ID
        {
            bytes memory encoded = hex"0100010004deadbeef";
            uint256 result = XChainLib.concatChainIdsSol(encoded, testChainId);
            assertEq(result, testChainId, "Should return testChainId when no match");

            result = XChainLib.concatChainIdsSol(encoded, 1);
            assertEq(result, 0x0001, "Single chain ID should be 0x0001 when it matches defChainId");
        }

        // Test with 2 chain IDs
        {
            bytes memory encoded = hex"0200010004deadbeef00020004cafebabe";
            uint256 result = XChainLib.concatChainIdsSol(encoded, testChainId);
            assertEq(result, testChainId, "Should return testChainId when no match");

            result = XChainLib.concatChainIdsSol(encoded, 1);
            assertEq(result, 0x00010002, "Concatenated chain IDs should be 0x00010002 when defChainId matches");
        }

        // Test with 4 chain IDs -- positive test case with defChainId matching
        {
            bytes memory encoded = hex"0400010001aa00050001bb00640001cc03e80001dd";
            uint256 result = XChainLib.concatChainIdsSol(encoded, 1);
            assertEq(
                result,
                0x00010005006403e8,
                "Concatenated chain IDs should be 0x00010005006403e8 when defChainId matches"
            );

            result = XChainLib.concatChainIdsSol(encoded, 100);
            assertEq(
                result,
                0x00010005006403e8,
                "Concatenated chain IDs should be 0x00010005006403e8 when defChainId matches any of the 4 chain IDs"
            );

            result = XChainLib.concatChainIdsSol(encoded, 1);
            assertEq(
                result,
                0x00010005006403e8,
                "Concatenated chain IDs should be 0x00010005006403e8 when defChainId matches"
            );
        }

        // Test with 4 chain IDs -- negative test case
        {
            bytes memory encoded = hex"0400010001aa00050001bb00640001cc03e80001dd";
            uint256 result = XChainLib.concatChainIdsSol(encoded, testChainId);
            assertEq(result, testChainId, "Should return testChainId when no match");
        }

        // Test with invalid data
        assertEq(
            XChainLib.concatChainIdsSol(hex"", testChainId), testChainId, "Empty data should return the testChainId"
        );

        assertEq(
            XChainLib.concatChainIdsSol(hex"deadbeef", testChainId),
            testChainId,
            "Invalid data should return the testChainId"
        );

        assertEq(
            XChainLib.concatChainIdsSol(hex"00", testChainId),
            testChainId,
            "Invalid number of ops should return the testChainId"
        );

        assertEq(
            XChainLib.concatChainIdsSol(hex"05", testChainId), testChainId, "Too many ops should return the testChainId"
        );

        // Test with conventional unprefixed calldata
        assertEq(
            XChainLib.concatChainIdsSol(hex"a9059cbb000000000000000000000000", testChainId),
            testChainId,
            "Conventional calldata should return the testChainId"
        );
    }

    function testYulConcatChainIds() public {
        uint256 testChainId = 31337; // Assuming this is the block.chainid in the test environment

        // Test with 1 chain ID
        {
            bytes memory encoded = hex"0100010004deadbeef";
            uint256 result = XChainLib.concatChainIds(encoded, testChainId);
            assertEq(result, testChainId, "Should return testChainId when no match");

            result = XChainLib.concatChainIds(encoded, 1);
            assertEq(result, 0x0001, "Single chain ID should be 0x0001 when it matches defChainId");
        }

        // Test with 2 chain IDs
        {
            bytes memory encoded = hex"0200010004deadbeef00020004cafebabe";
            uint256 result = XChainLib.concatChainIds(encoded, testChainId);
            assertEq(result, testChainId, "Should return testChainId when no match");

            result = XChainLib.concatChainIds(encoded, 1);
            assertEq(result, 0x00010002, "Concatenated chain IDs should be 0x00010002 when defChainId matches");
        }

        // Test with 4 chain IDs -- positive test case with defChainId matching
        {
            bytes memory encoded = hex"0400010001aa00050001bb00640001cc03e80001dd";
            uint256 result = XChainLib.concatChainIds(encoded, 1);
            assertEq(
                result,
                0x00010005006403e8,
                "Concatenated chain IDs should be 0x00010005006403e8 when defChainId matches"
            );

            result = XChainLib.concatChainIds(encoded, 100);
            assertEq(
                result,
                0x00010005006403e8,
                "Concatenated chain IDs should be 0x00010005006403e8 when defChainId matches any of the 4 chain IDs"
            );

            result = XChainLib.concatChainIds(encoded, 1);
            assertEq(
                result,
                0x00010005006403e8,
                "Concatenated chain IDs should be 0x00010005006403e8 when defChainId matches"
            );
        }

        // Test with 4 chain IDs -- negative test case
        {
            bytes memory encoded = hex"0400010001aa00050001bb00640001cc03e80001dd";
            uint256 result = XChainLib.concatChainIds(encoded, testChainId);
            assertEq(result, testChainId, "Should return testChainId when no match");
        }

        // Test with invalid data
        assertEq(XChainLib.concatChainIds(hex"", testChainId), testChainId, "Empty data should return the testChainId");
        assertEq(
            XChainLib.concatChainIds(hex"deadbeef", testChainId),
            testChainId,
            "Invalid data should return the testChainId"
        );
        assertEq(
            XChainLib.concatChainIds(hex"00", testChainId),
            testChainId,
            "Invalid number of ops should return the testChainId"
        );
        assertEq(
            XChainLib.concatChainIds(hex"05", testChainId), testChainId, "Too many ops should return the testChainId"
        );

        // Test with conventional unprefixed calldata
        assertEq(
            XChainLib.concatChainIds(hex"a9059cbb000000000000000000000000", testChainId),
            testChainId,
            "Conventional calldata should return the testChainId"
        );
    }

    function testGasConcatChainIdsComparison() public {
        bytes memory encoded =
            hex"0400010064000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002c8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        // Test Solidity version
        uint256 gasStartSolidity = gasleft();
        uint256 resultSolidity = XChainLib.concatChainIdsSol(encoded, block.chainid);
        uint256 gasUsedSolidity = gasStartSolidity - gasleft();

        // Test Assembly version
        uint256 gasStartAssembly = gasleft();
        uint256 resultAssembly = XChainLib.concatChainIds(encoded, block.chainid);
        uint256 gasUsedAssembly = gasStartAssembly - gasleft();

        console2.log("Gas used (Solidity):", gasUsedSolidity);
        console2.log("Gas used (Assembly):", gasUsedAssembly);
        console2.log("Gas saved:", gasUsedSolidity - gasUsedAssembly);

        assertEq(resultSolidity, resultAssembly, "Results should be the same for both implementations");
        assertTrue(gasUsedAssembly < gasUsedSolidity, "Assembly version should use less gas");
    }

    function testCombinedCallDataTooLong() public {
        XChainLib.xCallData[] memory ops = new XChainLib.xCallData[](3);
        ops[0] = XChainLib.xCallData(1, new bytes(XChainLib.MAX_CALLDATA_LENGTH));
        ops[1] = XChainLib.xCallData(2, new bytes(XChainLib.MAX_CALLDATA_LENGTH));
        ops[2] = XChainLib.xCallData(3, new bytes(1));

        vm.expectRevert(
            abi.encodeWithSelector(XChainLib.CombinedCallDataTooLong.selector, 2 * XChainLib.MAX_CALLDATA_LENGTH + 1)
        );
        TestSimpleAccountHelper.encodeXChainCallData(ops);
    }

    function testExtractNonExistentChainId() public {
        XChainLib.xCallData[] memory ops = new XChainLib.xCallData[](2);
        ops[0] = XChainLib.xCallData(1, hex"deadbeef");
        ops[1] = XChainLib.xCallData(2, hex"cafebabe");

        bytes memory encoded = TestSimpleAccountHelper.encodeXChainCallData(ops);
        assertEq(XChainLib.extractXChainCallData(encoded, 3), hex"");
    }

    function testInvalidEncodedData() public {
        vm.expectRevert(XChainLib.InvalidEncodedData.selector);
        XChainLib.extractXChainCallData(hex"", 1);
    }

    function testChainDataTooShort() public {
        bytes memory invalidEncoded = hex"0201"; // Only contains number of ops and partial chain ID
        vm.expectRevert(XChainLib.ChainDataTooShort.selector);
        XChainLib.extractXChainCallData(invalidEncoded, 1);
    }

    function testMaximumCallDataLength() public {
        XChainLib.xCallData[] memory ops = new XChainLib.xCallData[](1);
        ops[0] = XChainLib.xCallData(1, new bytes(XChainLib.MAX_CALLDATA_LENGTH));

        bytes memory encoded = TestSimpleAccountHelper.encodeXChainCallData(ops);
        assertEq(XChainLib.extractXChainCallData(encoded, 1).length, XChainLib.MAX_CALLDATA_LENGTH);
    }

    function testFourChainUserOp() public {
        XChainLib.xCallData[] memory ops = new XChainLib.xCallData[](4);
        ops[0] = XChainLib.xCallData(1, hex"11");
        ops[1] = XChainLib.xCallData(2, hex"2222");
        ops[2] = XChainLib.xCallData(3, hex"333333");
        ops[3] = XChainLib.xCallData(4, hex"44444444");

        bytes memory encoded = TestSimpleAccountHelper.encodeXChainCallData(ops);

        assertEq(XChainLib.extractXChainCallData(encoded, 1), hex"11");
        assertEq(XChainLib.extractXChainCallData(encoded, 2), hex"2222");
        assertEq(XChainLib.extractXChainCallData(encoded, 3), hex"333333");
        assertEq(XChainLib.extractXChainCallData(encoded, 4), hex"44444444");
    }

    function testExtractXChainCallDataGasCost() public {
        XChainLib.xCallData[] memory ops = new XChainLib.xCallData[](4);
        ops[0] = XChainLib.xCallData(1, new bytes(1000));
        ops[1] = XChainLib.xCallData(2, new bytes(2000));
        ops[2] = XChainLib.xCallData(3, new bytes(3000));
        ops[3] = XChainLib.xCallData(4, new bytes(1000));

        bytes memory encoded = TestSimpleAccountHelper.encodeXChainCallData(ops);

        uint256 gasStart = gasleft();
        bool isXChainCallData = XChainLib.isXChainCallData(encoded);
        assertEq(isXChainCallData, true);
        uint256 gasUsed = gasStart - gasleft();
        console2.log("Gas used for isXChainCallData (3):", gasUsed);

        gasStart = gasleft();
        bytes memory op1 = XChainLib.extractXChainCallData(encoded, 1);
        gasUsed = gasStart - gasleft();
        assertEq(op1, new bytes(1000));
        console2.log("Gas used for extractXChainCallData chain id(1):", gasUsed);

        gasStart = gasleft();
        bytes memory op3 = XChainLib.extractXChainCallData(encoded, 3);
        gasUsed = gasStart - gasleft();
        assertEq(op3, new bytes(3000));
        console2.log("Gas used for extractXChainCallData chain id(3):", gasUsed);
    }
}
