/*
Encode and concatenate multiple chain-specific Calldata into a single userOp calldata value.

Usage:
    go run concat.go <chain1_id>:<chain1_calldata> [<chain2_id>:<chain2_calldata>] [<chain3_id>:<chain3_calldata>] [<chain4_id>:<chain4_calldata>]

Arguments:
    <chainX_id>         Required. The chain ID for the UserOp. Must be a decimal number between 1 and 65535.
    <chainX_calldata>   Required. The calldata for the UserOp. Must be a hexadecimal string, optionally 0x-prefixed.

Examples:
    Encode single UserOp:
      go run main.go 1:0x1234567890abcdef

    Encode two UserOps:
      go run main.go 1:0x1234567890abcdef 2:0xfedcba9876543210

    Encode four UserOps:
      go run main.go 1:0x1234 2:0x5678 3:0x9abc 4:0xdef0
*/
package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	MAX_COMBINED_CALLDATA_LENGTH = 14336
	MAX_CALLDATA_LENGTH          = 7168
	MAX_CALLDATA_COUNT           = 4
)

var (
	ErrCombinedCallDataTooLong   = errors.New("combined calldata too long")
	ErrInvalidCallDataLength     = errors.New("invalid calldata length")
	ErrCallDataTooLong           = errors.New("calldata too long")
	ErrInvalidEncodedData        = errors.New("invalid encoded data")
	ErrInvalidNumberOfCallData   = errors.New("invalid number of calldata")
	ErrChainDataTooShort         = errors.New("chain data too short")
	ErrInvalidHexString          = errors.New("invalid hex string")
	ErrInvalidChainID            = errors.New("invalid chain ID")
)

// XCallData represents a single chain-specific UserOp
type XCallData struct {
	ChainID  uint16
	CallData []byte
}

// encodeXChainCallData encodes multiple chain-specific UserOps into a single byte array
// It implements the same logic and validations as the Solidity encodeXChainCallData function
func encodeXChainCallData(chainUserOps []XCallData) ([]byte, error) {
	// Validate number of UserOps
	if len(chainUserOps) == 0 || len(chainUserOps) > MAX_CALLDATA_COUNT {
		return nil, fmt.Errorf("%w: %d", ErrInvalidNumberOfCallData, len(chainUserOps))
	}

	// Initialize encoded result with number of UserOps
	encoded := make([]byte, 1)
	encoded[0] = byte(len(chainUserOps))

	callDataLengthTotal := 0
	for _, op := range chainUserOps {
		callDataLengthTotal += len(op.CallData)

		// Validate individual calldata length
		if len(op.CallData) > MAX_CALLDATA_LENGTH {
			return nil, fmt.Errorf("%w: %d", ErrCallDataTooLong, len(op.CallData))
		}

		// Validate combined calldata length
		if callDataLengthTotal > MAX_COMBINED_CALLDATA_LENGTH {
			return nil, fmt.Errorf("%w: %d", ErrCombinedCallDataTooLong, callDataLengthTotal)
		}

		// Encode chain ID (2 bytes, big-endian)
		chainIDBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(chainIDBytes, op.ChainID)

		// Encode calldata length (2 bytes, big-endian)
		callDataLengthBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(callDataLengthBytes, uint16(len(op.CallData)))

		// Append chain ID, calldata length, and calldata to the result
		encoded = append(encoded, chainIDBytes...)
		encoded = append(encoded, callDataLengthBytes...)
		encoded = append(encoded, op.CallData...)
	}

	return encoded, nil
}

// parseChainID converts a string to a uint16 chain ID and validates it
func parseChainID(s string) (uint16, error) {
	var chainID uint16
	_, err := fmt.Sscanf(s, "%d", &chainID)
	if err != nil {
		return 0, err
	}
	if chainID == 0 {
		return 0, ErrInvalidChainID
	}
	return chainID, nil
}

// parseSingleCalldata parses a single calldata argument in the format "chain_id:calldata"
func parseSingleCalldata(arg string) (XCallData, error) {
	parts := strings.SplitN(arg, ":", 2)
	if len(parts) != 2 {
		return XCallData{}, fmt.Errorf("invalid argument format: %s", arg)
	}

	chainID, err := parseChainID(parts[0])
	if err != nil {
		return XCallData{}, fmt.Errorf("invalid chain ID: %w", err)
	}

	callData, err := hex.DecodeString(strings.TrimPrefix(parts[1], "0x"))
	if err != nil {
		return XCallData{}, fmt.Errorf("invalid calldata: %w", err)
	}

	return XCallData{
		ChainID:  chainID,
		CallData: callData,
	}, nil
}

// parseCalldata parses all calldata arguments provided to the program
func parseCalldata(args []string) ([]XCallData, error) {
	var chainUserOps []XCallData

	for _, arg := range args {
		userOp, err := parseSingleCalldata(arg)
		if err != nil {
			return nil, err
		}
		chainUserOps = append(chainUserOps, userOp)
	}

	return chainUserOps, nil
}

func main() {
	// Validate command-line arguments
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run concat.go <chain1_id>:<chain1_calldata> [<chain2_id>:<chain2_calldata>] [<chain3_id>:<chain3_calldata>] [<chain4_id>:<chain4_calldata>]")
		os.Exit(1)
	}

	// Parse UserOps from command-line arguments
	chainUserOps, err := parseCalldata(os.Args[1:])
	if err != nil {
		fmt.Printf("Error parsing arguments: %s\n", err)
		os.Exit(1)
	}

	// Encode UserOps
	encoded, err := encodeXChainCallData(chainUserOps)
	if err != nil {
		fmt.Printf("Error encoding calldata: %s\n", err)
		os.Exit(1)
	}

	// Output the encoded result
	fmt.Printf("0x%s\n", hex.EncodeToString(encoded))
}