// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../libraries/EdOnBN254.sol";
import "../libraries/Transcript.sol";
import "../verifier/ChaumPedersenDLVerifier.sol";

struct MaskedCard {
    EdOnBN254.Point e1;
    EdOnBN254.Point e2;
}

contract RevealVerifier {
    function verifyReveal(
        EdOnBN254.Point memory pk,
        MaskedCard memory masked,
        EdOnBN254.Point memory reveal,
        bytes calldata proofBytes
    ) public view returns (bool) {
        require(proofBytes.length == 160, "VR001");
        // decode proof to ChaumPedersenDLProof (EdOnBN254.Point, EdOnBN254.Point, Fr)
        EdOnBN254.Point memory a = EdOnBN254.Point(
            uint256(bytes32(proofBytes[0:32])),
            uint256(bytes32(proofBytes[32:64]))
        );
        EdOnBN254.Point memory b = EdOnBN254.Point(
            uint256(bytes32(proofBytes[64:96])),
            uint256(bytes32(proofBytes[96:128]))
        );
        uint256 r = uint256(bytes32(proofBytes[128:160]));
        ChuamPerdensenDLProof memory proof = ChuamPerdensenDLProof(a, b, r);
        ChuamPerdensenDLParameters memory parameters = ChuamPerdensenDLParameters(masked.e1, EdOnBN254.generator());

        return ChuamPerdensenDLVerifier.verify(parameters, "Revealing", reveal, pk, proof);
    }

    function unmask(
        MaskedCard memory masked,
        EdOnBN254.Point[] memory reveals
    ) public view returns (EdOnBN254.Point memory) {
        EdOnBN254.Point memory aggregate = reveals[0];
        for (uint i = 1; i < reveals.length; i++) {
            aggregate = EdOnBN254.add(aggregate, reveals[i]);
        }
        return EdOnBN254.add(masked.e2, EdOnBN254.neg(aggregate));
    }
}
