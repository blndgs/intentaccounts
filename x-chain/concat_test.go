package main

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestEncodeXChainCallData(t *testing.T) {
	tests := []struct {
		name         string
		chainUserOps []XCallData
		want         string
		wantErr      bool
	}{
		{
			name: "Single UserOp",
			chainUserOps: []XCallData{
				{ChainID: 1, CallData: []byte{0xde, 0xad, 0xbe, 0xef}},
			},
			want:    "0100010004deadbeef",
			wantErr: false,
		},
		{
			name: "Two UserOps",
			chainUserOps: []XCallData{
				{ChainID: 1, CallData: []byte{0xde, 0xad, 0xbe, 0xef}},
				{ChainID: 2, CallData: []byte{0xca, 0xfe, 0xba, 0xbe}},
			},
			want:    "0200010004deadbeef00020004cafebabe",
			wantErr: false,
		},
		{
			name: "Four UserOps",
			chainUserOps: []XCallData{
				{ChainID: 1, CallData: []byte{0xaa}},
				{ChainID: 5, CallData: []byte{0xbb}},
				{ChainID: 100, CallData: []byte{0xcc}},
				{ChainID: 1000, CallData: []byte{0xdd}},
			},
			want:    "0400010001aa00050001bb00640001cc03e80001dd",
			wantErr: false,
		},
		{
			name:         "Empty UserOps",
			chainUserOps: []XCallData{},
			want:         "",
			wantErr:      true,
		},
		{
			name: "Too many UserOps",
			chainUserOps: []XCallData{
				{ChainID: 1, CallData: []byte{0xaa}},
				{ChainID: 2, CallData: []byte{0xbb}},
				{ChainID: 3, CallData: []byte{0xcc}},
				{ChainID: 4, CallData: []byte{0xdd}},
				{ChainID: 5, CallData: []byte{0xee}},
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeXChainCallData(tt.chainUserOps)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeXChainCallData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				wantBytes, _ := hex.DecodeString(tt.want)
				if !bytes.Equal(got, wantBytes) {
					t.Errorf("EncodeXChainCallData() = %x, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestConcatChainIds(t *testing.T) {
	tests := []struct {
		name        string
		encodedData string
		defChainId  uint64
		want        uint64
	}{
		{
			name:        "Single chain ID matching",
			encodedData: "0100010004deadbeef",
			defChainId:  1,
			want:        0x0001,
		},
		{
			name:        "Single chain ID not matching",
			encodedData: "0100010004deadbeef",
			defChainId:  2,
			want:        2,
		},
		{
			name:        "Two chain IDs, first matching",
			encodedData: "0200010004deadbeef00020004cafebabe",
			defChainId:  1,
			want:        0x00010002,
		},
		{
			name:        "Two chain IDs, second matching",
			encodedData: "0200010004deadbeef00020004cafebabe",
			defChainId:  2,
			want:        0x00010002,
		},
		{
			name:        "Two chain IDs, none matching",
			encodedData: "0200010004deadbeef00020004cafebabe",
			defChainId:  3,
			want:        3,
		},
		{
			name:        "Four chain IDs, third matching",
			encodedData: "0400010001aa00050001bb00640001cc03e80001dd",
			defChainId:  100,
			want:        0x00010005006403e8,
		},
		{
			name:        "Four chain IDs, none matching",
			encodedData: "0400010001aa00050001bb00640001cc03e80001dd",
			defChainId:  31337,
			want:        31337,
		},
		{
			name:        "Empty data",
			encodedData: "",
			defChainId:  31337,
			want:        31337,
		},
		{
			name:        "Invalid data",
			encodedData: "deadbeef",
			defChainId:  31337,
			want:        31337,
		},
		{
			name:        "Invalid number of ops",
			encodedData: "00",
			defChainId:  31337,
			want:        31337,
		},
		{
			name:        "Too many ops",
			encodedData: "05",
			defChainId:  31337,
			want:        31337,
		},
		{
			name:        "Conventional unprefixed calldata",
			encodedData: "a9059cbb000000000000000000000000",
			defChainId:  31337,
			want:        31337,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encodedData, _ := hex.DecodeString(tt.encodedData)
			if got := getXChainIds(encodedData, tt.defChainId); got != tt.want {
				t.Errorf("getXChainIds() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseEncodedCalldata(t *testing.T) {
	tests := []struct {
		name          string
		encodedData   string
		wantNumOps    uint8
		wantChainIds  []uint16
		wantCalldatas []string
		wantErr       bool
	}{
		{
			name:          "Valid data with 4 operations",
			encodedData:   "0400010001aa00050001bb00640001cc03e80001dd",
			wantNumOps:    4,
			wantChainIds:  []uint16{0x0001, 0x0005, 0x0064, 0x03e8},
			wantCalldatas: []string{"aa", "bb", "cc", "dd"},
			wantErr:       false,
		},
		{
			name:          "Invalid number of operations",
			encodedData:   "05",
			wantNumOps:    0,
			wantChainIds:  nil,
			wantCalldatas: nil,
			wantErr:       true,
		},
		{
			name:          "Insufficient data",
			encodedData:   "01000100",
			wantNumOps:    0,
			wantChainIds:  nil,
			wantCalldatas: nil,
			wantErr:       true,
		},
		{
			name:          "Extra data at the end",
			encodedData:   "0100010001aaff",
			wantNumOps:    0,
			wantChainIds:  nil,
			wantCalldatas: nil,
			wantErr:       true,
		},
		{
			name:         "Long valid calldata",
			encodedData:  "0400010080aaaa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000aaaa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200c8bbbb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300bccccc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cccc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffff0100dddd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dddd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			wantNumOps:   4,
			wantChainIds: []uint16{0x0001, 0x0002, 0x0003, 0xffff},
			wantCalldatas: []string{
				"aaaa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000aaaa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"bbbb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"cccc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cccc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"dddd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dddd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encodedData, err := hex.DecodeString(strings.TrimPrefix(tt.encodedData, "0x"))
			if (err != nil) != tt.wantErr {
				t.Errorf("hex.DecodeString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotNumOps, gotChainIds, gotCalldatas, err := ParseEncodedCalldata(encodedData)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEncodedCalldata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if gotNumOps != tt.wantNumOps {
					t.Errorf("ParseEncodedCalldata() gotNumOps = %v, want %v", gotNumOps, tt.wantNumOps)
				}

				if !reflect.DeepEqual(gotChainIds, tt.wantChainIds) {
					t.Errorf("ParseEncodedCalldata() gotChainIds = %v, want %v", gotChainIds, tt.wantChainIds)
				}

				if len(gotCalldatas) != len(tt.wantCalldatas) {
					t.Errorf("ParseEncodedCalldata() gotCalldatas length = %d, want %d", len(gotCalldatas), len(tt.wantCalldatas))
				} else {
					for i, calldata := range gotCalldatas {
						if hex.EncodeToString(calldata) != tt.wantCalldatas[i] {
							t.Errorf("ParseEncodedCalldata() gotCalldatas[%d] = %s, want %s", i, hex.EncodeToString(calldata), tt.wantCalldatas[i])
						}
					}
				}
			}
		})
	}
}
