// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

library ExternalTranscript {
    function load(uint256 loc) internal pure {
        assembly {
            mstore(loc, 2) // the length
            mstore(add(loc, 0x20), 0x506c6f6e6b2073687566666c652050726f6f66)
            mstore(add(loc, 0x40), 52)
        }
    }
}
