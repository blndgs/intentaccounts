#!/bin/bash

# Function to validate hexadecimal input
validate_hex() {
    if ! [[ $1 =~ ^0x[0-9a-fA-F]+$ ]]; then
        echo "Error: Invalid hexadecimal input '$1'. Must start with '0x' followed by hexadecimal digits."
        exit 1
    fi
}

# Function to encode calldata
encode_calldata() {
    local SOURCE_CALLDATA=$1
    local DEST_CALLDATA=$2

    # Validate inputs
    validate_hex "$SOURCE_CALLDATA"
    if [ -n "$DEST_CALLDATA" ]; then
        validate_hex "$DEST_CALLDATA"
    fi

    # Calculate source calldata length (in bytes)
    local SOURCE_LENGTH=$((${#SOURCE_CALLDATA} / 2 - 1))  # Subtract 1 to account for '0x' prefix

    # Encode the length as a 2-byte hex string
    local ENCODED_LENGTH=$(cast --to-uint256 $SOURCE_LENGTH | cut -c 63-66)

    # Concatenate the encoded length with the source calldata
    local RESULT="0x${ENCODED_LENGTH}${SOURCE_CALLDATA:2}"

    # If destination calldata is provided, append it
    if [ -n "$DEST_CALLDATA" ]; then
        RESULT="${RESULT}${DEST_CALLDATA:2}"
    fi

    echo "$RESULT"
}

# Main script logic
if [ "$#" -eq 1 ]; then
    # Only source calldata provided
    RESULT=$(encode_calldata "$1")
    echo "Encoded result (source only): $RESULT"
elif [ "$#" -eq 2 ]; then
    # Both source and destination calldata provided
    RESULT=$(encode_calldata "$1" "$2")
    echo "Encoded result (source and destination): $RESULT"
else
    echo "Usage: $0 <source_calldata> [destination_calldata]"
    echo "Example (source only): $0 0x1234567890abcdef"
    echo "Example (source and destination): $0 0x1234567890abcdef 0xfedcba9876543210"
    exit 1
fi
