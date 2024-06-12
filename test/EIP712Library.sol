// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {KERNEL_NAME, KERNEL_VERSION, VALIDATOR_APPROVED_STRUCT_HASH} from "../lib/kernel/src/common/Constants.sol";

library EIP712Library {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    function _buildDomainSeparator(string memory name, string memory version, address account)
        private
        view
        returns (bytes32 separator)
    {
        bytes32 nameHash = keccak256(bytes(name));
        bytes32 versionHash = keccak256(bytes(version));

        separator = keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, nameHash, versionHash, block.chainid, account));
    }

    /// @dev Returns the hash of the fully encoded EIP-712 message for this domain,
    /// given `structHash`, as defined in
    /// https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct.
    ///
    /// The hash can be used together with {ECDSA-recover} to obtain the signer of a message:
    /// ```
    ///     bytes32 digest = _hashTypedData(keccak256(abi.encode(
    ///         keccak256("Mail(address to,string contents)"),
    ///         mailTo,
    ///         keccak256(bytes(mailContents))
    ///     )));
    ///     address signer = ECDSA.recover(digest, signature);
    /// ```
    function hashTypedData(string calldata name, string calldata version, bytes32 structHash, address account)
        public
        view
        returns (bytes32 digest)
    {
        bytes32 separator = _buildDomainSeparator(name, version, account);

        return keccak256(abi.encodePacked(bytes2(0x1901), separator, structHash));
    }

    // computes the hash of a permit
    function getStructHash(
        bytes4 sig,
        uint48 validUntil,
        uint48 validAfter,
        address validator,
        address executor,
        bytes memory enableData
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                VALIDATOR_APPROVED_STRUCT_HASH,
                bytes4(sig),
                // [         validUntil         ][         validAfter         ][            validator           ]
                // [       48 bits (208-255)    ][       48 bits (160-207)    ][          160 bits (0-159)      ]
                (uint256(validUntil) << 208) | (uint256(validAfter) << 160) | uint256(uint160(validator)),
                executor,
                keccak256(enableData)
            )
        );
    }
}
