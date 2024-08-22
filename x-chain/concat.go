/*
Encode a single piece of calldata or combine two pieces, prepending the length of the source
calldata as a 2-byte prefix to the encoded result.

Usage:
	go run ethereum_calldata_encoder.go <source_calldata> [destination_calldata]

Arguments:

	<source_calldata>      Required. The source chain calldata to encode. Must be a 0x-prefixed.
	[destination_calldata] Optional. The destination chain calldata to append. Must be a 0x-prefixed.

Examples:

	Encode single calldata:
	  go run concat.go 0x1234567890abcdef

	Encode and combine two pieces of calldata:
	  go run concat.go 0x1234567890abcdef 0xfedcba9876543210
*/
package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"os"
	"regexp"
)

// validateHex checks if the input is a valid hexadecimal string
func validateHex(input string) error {
	match, _ := regexp.MatchString("^0x[0-9a-fA-F]+$", input)
	if !match {
		return fmt.Errorf("invalid hexadecimal input '%s'. Must start with '0x' followed by hexadecimal digits", input)
	}
	return nil
}

// encodeCalldata encodes the calldata with a length prefix and optional destination calldata.
// It asserts that the decoding process reproduces the original calldata.
func encodeCalldata(sourceCalldata string, destCalldata string) (string, error) {
	// Validate inputs
	if err := validateHex(sourceCalldata); err != nil {
		return "", err
	}
	if destCalldata != "" {
		if err := validateHex(destCalldata); err != nil {
			return "", err
		}
	}

	// Calculate source calldata length (in bytes)
	sourceLengthHeur := (len(sourceCalldata) - 2) / 2 // Subtract 2 to account for '0x' prefix
	sourceBytes, err := hexToBytes(sourceCalldata)
	if err != nil {
		panic(fmt.Errorf("error converting source calldata to bytes: %v", err))
	}
	sourceLength := len(sourceBytes)

	// Assert that the heuristic length matches the actual length
	if sourceLength != sourceLengthHeur {
		panic(fmt.Errorf("calldata length mismatch. Expected %d bytes, got %d", sourceLength, sourceLengthHeur))
	}

	// Encode the length as a 2-byte hex string
	encodedLength := fmt.Sprintf("%04x", sourceLength)

	// Concatenate the encoded length with the source calldata
	result := "0x" + encodedLength + sourceCalldata[2:]

	// If destination calldata is provided, append it
	if destCalldata != "" {
		result += destCalldata[2:]
	}

	// Assert that the decoding reproduces the original
	decSource, decDest := decodeCalldata(result)
	if decSource != sourceCalldata {
		panic(fmt.Errorf("source calldata mismatch. Expected %s, got %s", sourceCalldata, decSource))
	}
	if decDest != destCalldata {
		panic(fmt.Errorf("destination calldata mismatch. Expected %s, got %s", destCalldata, decDest))
	}

	return result, nil
}

func decodeCalldata(encodedCalldata string) (string, string) {
	// Validate input
	if err := validateHex(encodedCalldata); err != nil {
		panic(err)
	}

	// Extract the length prefix
	lengthPrefix := encodedCalldata[2:6]
	length := hexutil.MustDecodeUint64("0x" + lengthPrefix)

	// Extract the source calldata
	sourceCalldata := "0x" + encodedCalldata[6:6+length*2]

	// Extract the destination calldata if it exists
	var destCalldata string
	if len(encodedCalldata) > 6+int(length)*2 {
		destCalldata = "0x" + encodedCalldata[6+length*2:]
	}

	return sourceCalldata, destCalldata
}

func main() {
	args := os.Args[1:]

	if len(args) == 1 {
		// Only source calldata provided
		result, err := encodeCalldata(args[0], "")
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		fmt.Printf("Encoded result (source only):\n%s", result)
	} else if len(args) == 2 {
		// Both source and destination calldata provided
		result, err := encodeCalldata(args[0], args[1])
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		fmt.Printf("Encoded result (source and destination):\n%s", result)
	} else {
		// Unknown
		fmt.Println("Usage:", os.Args[0], "<source_calldata> [destination_calldata]")
		fmt.Println("Example (source only):", os.Args[0], "0x1234567890abcdef")
		fmt.Println("Example (source and destination):", os.Args[0], "0x1234567890abcdef 0xfedcba9876543210")
		os.Exit(1)
	}
}

func hexToBytes(hex string) ([]byte, error) {
	return hexutil.Decode(hex)
}

func bytesToHex(b []byte) string {
	return hexutil.Encode(b)
}
