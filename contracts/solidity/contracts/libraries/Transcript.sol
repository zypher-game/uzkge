// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "./BytesLib.sol";
import "./Utils.sol";
import "./BN254.sol";
import "./EdOnBN254.sol";

library Transcript {
    struct TranscriptData {
        bytes state;
    }

    function appendMessage(TranscriptData memory self, bytes memory message) internal pure {
        if (message.length < 32) {
            bytes memory ret = new bytes(32);
            uint256 start = 32 - message.length;
            for (uint i = 0; i < message.length; i++) {
                ret[start + i] = message[i];
            }
            self.state = abi.encodePacked(self.state, ret);
        } else {
            self.state = abi.encodePacked(self.state, message);
        }
    }

    function appendUint256(TranscriptData memory self, uint256 u256) internal pure {
        self.state = abi.encodePacked(self.state, u256);
    }

    function getAndAppendChallenge(TranscriptData memory self, uint256 q) internal pure returns (uint256) {
        bytes32 hash = keccak256(self.state);
        self.state = abi.encodePacked(hash);
        return uint256(hash) % q;
    }
}
