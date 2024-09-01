/*
Package xchainlib provides functionality for encoding and decoding cross-chain call data,
as well as concatenating chain IDs from encoded data.

This package includes functions for:
- Encoding multiple chain-specific UserOps into a single byte array
- Concatenating chain IDs from encoded cross-chain call data
- Parsing encoded calldata to extract chain IDs and individual calldata values

The getXChainIds function now implements the following behavior:
- It concatenates chain IDs from the encoded data only if at least one of the parsed chain IDs matches the provided default chain ID.
- If no parsed chain ID matches the default chain ID, or if the input is invalid, it returns the default chain ID.

Usage:

	Encode mode:
	    go run concat.go <chain1_id>:<chain1_calldata> [<chain2_id>:<chain2_calldata>] [<chain3_id>:<chain3_calldata>] [<chain4_id>:<chain4_calldata>]

	Parse mode:
	    go run concat.go -p <encoded_calldata>

	Concatenate mode:
	    go run concat.go -c <encoded_calldata> [default_chain_id]

Arguments:

	<chainX_id>         Required in encode mode. The chain ID for the UserOp. Must be a decimal number between 1 and 65535.
	<chainX_calldata>   Required in encode mode. The calldata for the UserOp. Must be a hexadecimal string, optionally 0x-prefixed.
	<encoded_calldata>  Required in parse and concatenate modes. The encoded calldata to be parsed or concatenated. Must be a hexadecimal string, optionally 0x-prefixed.
	<default_chain_id>  Required in concatenate mode. The default chain ID (block.chainid) to return if no parsed chain ID matches or if the encoded data is invalid. Must be a decimal number.

Flags:

	-p                  Enable parse mode. When set, the program will parse the provided encoded calldata.
	-c                  Enable concatenate mode. When set, the program will concatenate chain IDs from the provided encoded calldata.

Examples:

	Encode single UserOp:
	  go run concat.go 1:0x1234567890abcdef

0x01000100081234567890abcdef

	Encode two UserOps:
	  go run concat.go 1:0x1234567890abcdef 2:0xfedcba9876543210

0x02000100081234567890abcdef00020008fedcba9876543210

	Parse encoded calldata:
	  go run concat.go -p 0x0200010004deadbeef00020004cafebabe

Number of operations: 2
Operation 1:

	Chain ID: 1
	Calldata: 0xdeadbeef

Operation 2:

	  Chain ID: 2
	  Calldata: 0xcafebabe

		Concatenate chain IDs:
		  go run concat.go -c 0x0400010001aa00050001bb00640001cc03e80001dd 5

0x00010005006403e8

	go run concat.go -c 0x0400010001aa00050001bb00640001cc03e80001dd 31337

0x00010005006403e8

Output:

	Encode mode: Outputs the encoded calldata as a hexadecimal string.
	Parse mode: Outputs the number of operations, chain IDs, and individual calldata values.
	Concatenate mode: Outputs the concatenated chain IDs as a hexadecimal string if at least one parsed chain ID matches the default chain ID,
	                  otherwise outputs the default chain ID.

Note:

	The getXChainIds function now returns the concatenated chain IDs only if at least one of the parsed chain IDs matches the provided default chain ID.
	If no match is found, or if the input is invalid, it returns the default chain ID. This ensures that the function only returns a concatenated result
	when at least one of the encoded operations is intended for the current chain (as specified by the default chain ID).
*/
package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	MAX_COMBINED_CALLDATA_LENGTH = 14336
	MAX_CALLDATA_LENGTH          = 7168
	MAX_CALLDATA_COUNT           = 4
)

var (
	ErrCombinedCallDataTooLong = errors.New("combined calldata too long")
	ErrInvalidCallDataLength   = errors.New("invalid calldata length")
	ErrCallDataTooLong         = errors.New("calldata too long")
	ErrInvalidEncodedData      = errors.New("invalid encoded data")
	ErrInvalidNumberOfCallData = errors.New("invalid number of calldata")
	ErrZeroChainID             = errors.New("chaiin ID cannot be zero")
)

// XCallData represents a single chain-specific UserOp
type XCallData struct {
	ChainID  uint16
	CallData []byte
}

func main() {
	parseMode := flag.Bool("p", false, "Enable parse mode")
	concatMode := flag.Bool("c", false, "Enable concatenate mode")
	flag.Parse()

	args := flag.Args()

	if *parseMode {
		handleParseMode(args)
	} else if *concatMode {
		handleConcatMode(args)
	} else {
		handleEncodeMode(args)
	}
}

func handleEncodeMode(args []string) {
	if len(args) < 2 || len(args) > 4 {
		fmt.Println("Error: Invalid number of arguments. Attempting to encode a multichain calldata (default mode). Please provide 2 to 4 chain_id:calldata pairs.")
		os.Exit(1)
	}

	var chainUserOps []XCallData
	for _, arg := range args {
		parts := strings.Split(arg, ":")
		if len(parts) != 2 {
			fmt.Printf("Error: Invalid argument format: %s\n", arg)
			os.Exit(1)
		}

		chainID, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			fmt.Printf("Error: Invalid chain ID: %s\n", parts[0])
			os.Exit(1)
		}

		calldata, err := hex.DecodeString(strings.TrimPrefix(parts[1], "0x"))
		if err != nil {
			fmt.Printf("Error: Invalid calldata: %s\n", parts[1])
			os.Exit(1)
		}

		chainUserOps = append(chainUserOps, XCallData{
			ChainID:  uint16(chainID),
			CallData: calldata,
		})
	}

	encoded, err := EncodeXChainCallData(chainUserOps)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("0x%s\n", hex.EncodeToString(encoded))
}

func handleParseMode(args []string) {
	if len(args) != 1 {
		fmt.Println("Error: Parse mode requires exactly one argument (encoded calldata).")
		os.Exit(1)
	}

	encodedValue := args[0]
	if strings.HasPrefix(encodedValue, "0x") {
		encodedValue = strings.TrimPrefix(encodedValue, "0x")
	}
	encodedData, err := hex.DecodeString(encodedValue)
	if err != nil {
		fmt.Printf("Error: Invalid encoded calldata: %s\n", args[0])
		os.Exit(1)
	}

	numOps, chainIDs, calldatas, err := ParseEncodedCalldata(encodedData)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Number of operations: %d\n", numOps)
	for i := 0; i < int(numOps); i++ {
		fmt.Printf("Operation %d:\n", i+1)
		fmt.Printf("  Chain ID: %d\n", chainIDs[i])
		fmt.Printf("  Calldata: 0x%s\n", hex.EncodeToString(calldatas[i]))
	}
}

func are2BytesHex(s string) (uint64, bool) {
	val, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	hexVal := binary.BigEndian.Uint16(val)
	return uint64(hexVal), err == nil
}

func handleConcatMode(args []string) {
	if len(args) != 2 {
		fmt.Println("Error: Concatenate mode requires 2 arguments (encoded calldata and default chain ID).")
		os.Exit(1)
	}

	encodedData, err := hex.DecodeString(strings.TrimPrefix(args[0], "0x"))
	if err != nil {
		fmt.Printf("Error: Invalid encoded calldata: %s\n", args[0])
		os.Exit(1)
	}

	var targetChainID uint64
	if len(args) == 2 {
		ok := false
		// check if args[1] is a valid hexdecimal number
		targetChainID, ok = are2BytesHex(args[1])

		if !ok {
			// try as a decimal number
			targetChainID, err = strconv.ParseUint(args[1], 10, 64)
			if err != nil {
				fmt.Printf("Error: Invalid target chain ID: %s\n", args[1])
				os.Exit(1)
			}
		}
	}

	result := getXChainIds(encodedData, targetChainID)
	fmt.Printf("0x%016x\n", result)
}

// EncodeXChainCallData encodes multiple chain-specific UserOps into a single byte array
func EncodeXChainCallData(chainUserOps []XCallData) ([]byte, error) {
	if len(chainUserOps) == 0 || len(chainUserOps) > MAX_CALLDATA_COUNT {
		return nil, fmt.Errorf("%w: %d", ErrInvalidNumberOfCallData, len(chainUserOps))
	}

	encoded := make([]byte, 1)
	encoded[0] = byte(len(chainUserOps))

	callDataLengthTotal := 0
	for _, op := range chainUserOps {
		callDataLengthTotal += len(op.CallData)

		if len(op.CallData) > MAX_CALLDATA_LENGTH {
			return nil, fmt.Errorf("%w: %d", ErrCallDataTooLong, len(op.CallData))
		}

		if callDataLengthTotal > MAX_COMBINED_CALLDATA_LENGTH {
			return nil, fmt.Errorf("%w: %d", ErrCombinedCallDataTooLong, callDataLengthTotal)
		}

		chainIDBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(chainIDBytes, op.ChainID)

		callDataLengthBytes := make([]byte, 2)
		callDataLength := uint16(len(op.CallData))
		binary.BigEndian.PutUint16(callDataLengthBytes, callDataLength)

		encoded = append(encoded, chainIDBytes...)
		encoded = append(encoded, callDataLengthBytes...)
		encoded = append(encoded, op.CallData...)
	}

	return encoded, nil
}

// getXChainIds provides the cross-chain chain_id for a multichain userOp by concatenating
// chain IDs from encoded cross-chain call data into a single uint64 value.
//
// This function extracts and combines chain IDs from the encoded data structure,
// preserving their original order. The resulting cross-chain chain_id indicates which
// chains the userOp is authorized for when signing it. The concatIds is a packed uint64 where:
//   - The most significant 16 bits contain the first operation's chain ID.
//   - Each subsequent 16-bit segment contains the next operation's chain ID.
//   - Up to 4 chain IDs can be packed, utilizing at most 64 bits.
//
// For example, given chain IDs [0x0001, 0x0005, 0x0064, 0x03E8], the output would be:
// 0x0001000500640388
// Which breaks down as:
//   - 0x0001 (Most significant 16 bits, representing chain ID 1)
//   - 0x0005 (Next 16 bits, representing chain ID 5)
//   - 0x0064 (Next 16 bits, representing chain ID 100)
//   - 0x03E8 (Least significant 16 bits, representing chain ID 1000)
//
// Visualized in 16-bit segments: 0x0001 | 0x0005 | 0x0064 | 0x03E8
//
// The function returns targetChainId if:
//   - Any parsed chain id is 0.
//   - the targetChainId is 0 or exceeds MAX_CHAIN_ID.
//   - The input data is invalid or cannot be parsed.
//   - None of the parsed chain IDs match the targetChainId.
//   - The input is a conventional single userOp non-prefixed calldata.
//   - The number of operations is less than 2 or more than 4.
//
// Parameters:
//
//	encodedData: The encoded cross-chain call data containing chain IDs and their associated call data.
//	targetChainId: The current block chain ID. This returns in case of invalid input or no matching chain ID.
//
// Returns:
//
//	concatIds: A uint64 value with concatenated chain IDs, ordered from most to least significant bits,
//	           representing the cross-chain chain_id for authorization, or targetChainId if conditions are not met.
func getXChainIds(encodedData []byte, targetChainID uint64) uint64 {
	const MaxChainId = 0xffff

	if targetChainID > MaxChainId {
		return targetChainID
	}

	if len(encodedData) < 5 {
		return targetChainID
	}

	numOps := uint8(encodedData[0])
	if numOps < 2 || numOps > 4 {
		return targetChainID
	}

	var concatIds uint64
	offset := 1
	matchFound := false

	for i := uint8(0); i < numOps; i++ {
		if offset+4 > len(encodedData) {
			return targetChainID
		}

		chainId := binary.BigEndian.Uint16(encodedData[offset : offset+2])
		if chainId == 0 {
			return targetChainID
		}
		if uint64(chainId) == targetChainID {
			matchFound = true
		}
		concatIds = (concatIds << 16) | uint64(chainId)

		calldataLength := binary.BigEndian.Uint16(encodedData[offset+2 : offset+4])
		offset += 4 + int(calldataLength)

		if offset > len(encodedData) {
			return targetChainID
		}
	}

	if offset != len(encodedData) {
		return targetChainID
	}

	if !matchFound {
		return targetChainID
	}

	return concatIds
}

// ParseEncodedCalldata parses the encoded calldata and returns the number of operations,
// slice of chain IDs, and parsed calldata values
func ParseEncodedCalldata(encodedData []byte) (uint8, []uint16, [][]byte, error) {
	if len(encodedData) < 5 {
		return 0, nil, nil, ErrInvalidEncodedData
	}

	numOps := uint8(encodedData[0])
	if numOps < 2 || numOps > 4 {
		return 0, nil, nil, ErrInvalidNumberOfCallData
	}

	var chainIds []uint16
	var calldatas [][]byte
	offset := 1

	for i := uint8(0); i < numOps; i++ {
		if offset+4 > len(encodedData) {
			return 0, nil, nil, fmt.Errorf("%w: \"offset+4 > len(encodedData)\" processing %d time (1..4), offset:%d, encodedDataLength:%d", ErrInvalidEncodedData, i+1, offset, len(encodedData))
		}

		chainId := binary.BigEndian.Uint16(encodedData[offset : offset+2])
		if chainId == 0 {
			return 0, nil, nil, fmt.Errorf("%w: while processing %d time (1..4)", ErrZeroChainID, i+1)
		}
		chainIds = append(chainIds, chainId)

		calldataLength := binary.BigEndian.Uint16(encodedData[offset+2 : offset+4])
		offset += 4

		if offset+int(calldataLength) > len(encodedData) {
			return 0, nil, nil, fmt.Errorf("%w: \"offset+int(calldataLength) > len(encodedData)\" processing %d time (1..4), offset:%d, calldataLength:%d, encodedDataLength:%d", ErrInvalidEncodedData, i+1, offset, calldataLength, len(encodedData))
		}

		calldatas = append(calldatas, encodedData[offset:offset+int(calldataLength)])
		offset += int(calldataLength)
	}

	if offset != len(encodedData) {
		return 0, nil, nil, fmt.Errorf("%w: final check \"offset != len(encodedData)\", offset:%d, encodedDataLend:%d", ErrInvalidEncodedData, offset, len(encodedData))
	}

	return numOps, chainIds, calldatas, nil
}
