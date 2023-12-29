// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "./BytesLib.sol";
import "./Utils.sol";
import "./BN254.sol";
import "./EdOnBN254.sol";

library Transcript {
    struct TranscriptData {
        bytes transcript;
        bytes32[2] state;
    }

    function appendMessage(
        TranscriptData memory self,
        bytes memory message
    ) internal pure {
        self.transcript = abi.encodePacked(self.transcript, message);
    }

    function appendUint256(
        TranscriptData memory self,
        uint256 u256
    ) internal pure {
        appendMessage(self, abi.encodePacked(Utils.reverseEndianness(u256)));
    }

    function appendFieldElement(
        TranscriptData memory self,
        uint256 fieldElement
    ) internal pure {
        appendUint256(self, fieldElement);
    }

    function appendFieldElements(
        TranscriptData memory self,
        uint256[] memory fieldElement
    ) internal pure {
        for (uint256 i = 0; i < fieldElement.length; i++) {
            appendFieldElement(self, fieldElement[i]);
        }
    }

    function appendCommitment(
        TranscriptData memory self,
        BN254.G1Point memory comm
    ) internal pure {
        bytes memory commBytes = BN254.g1Serialize(comm);
        appendMessage(self, commBytes);
    }

    function appendCommitments(
        TranscriptData memory self,
        BN254.G1Point[] memory comms
    ) internal pure {
        for (uint256 i = 0; i < comms.length; i++) {
            appendCommitment(self, comms[i]);
        }
    }

    function appendCommitmentEdOnBN254(
        TranscriptData memory self,
        EdOnBN254.Point memory comm
    ) internal pure {
        bytes memory commBytes = EdOnBN254.serialize(comm);
        appendMessage(self, commBytes);
    }

    function getAndAppendChallenge(
        TranscriptData memory self
    ) internal pure returns (uint256) {
        bytes32 h1 = keccak256(
            abi.encodePacked(
                self.state[0],
                self.state[1],
                self.transcript,
                uint8(0)
            )
        );
        bytes32 h2 = keccak256(
            abi.encodePacked(
                self.state[0],
                self.state[1],
                self.transcript,
                uint8(1)
            )
        );

        self.state[0] = h1;
        self.state[1] = h2;

        return
            BN254.fromLeBytesModOrder(
                BytesLib.slice(abi.encodePacked(h1, h2), 0, 48)
            );
    }
}
