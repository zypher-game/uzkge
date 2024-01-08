// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "../libraries/EdOnBN254.sol";
import "../libraries/Transcript.sol";

struct ChuamPerdensenDLParameters {
    EdOnBN254.Point g;
    EdOnBN254.Point h;
}

struct ChuamPerdensenDLProof {
    EdOnBN254.Point a;
    EdOnBN254.Point b;
    uint256 r;
}

library ChuamPerdensenDLVerifier {
    using Transcript for Transcript.TranscriptData;

    function verify(
        ChuamPerdensenDLParameters memory parameters,
        bytes memory externalInputTranscript,
        EdOnBN254.Point memory c1,
        EdOnBN254.Point memory c2,
        ChuamPerdensenDLProof memory proof
    ) internal view returns (bool) {
        Transcript.TranscriptData memory transcript;
        transcript.appendMessage(externalInputTranscript);

        // init transcript
        transcript.appendMessage("DL");
        transcript.appendUint256(parameters.g.x);
        transcript.appendUint256(parameters.g.y);
        transcript.appendUint256(parameters.h.x);
        transcript.appendUint256(parameters.h.y);
        transcript.appendUint256(c1.x);
        transcript.appendUint256(c1.y);
        transcript.appendUint256(c2.x);
        transcript.appendUint256(c2.y);
        transcript.appendUint256(proof.a.x);
        transcript.appendUint256(proof.a.y);
        transcript.appendUint256(proof.b.x);
        transcript.appendUint256(proof.b.y);

        uint256 c = transcript.getAndAppendChallenge(EdOnBN254.R);

        EdOnBN254.Point memory r1Left = EdOnBN254.scalarMul(parameters.g, proof.r);
        EdOnBN254.Point memory r1Right = EdOnBN254.add(proof.a, EdOnBN254.scalarMul(c1, c));
        if (!EdOnBN254.eq(r1Left, r1Right)) {
            return false;
        }

        EdOnBN254.Point memory r2Left = EdOnBN254.scalarMul(parameters.h, proof.r);
        EdOnBN254.Point memory r2Right = EdOnBN254.add(proof.b, EdOnBN254.scalarMul(c2, c));
        if (!EdOnBN254.eq(r2Left, r2Right)) {
            return false;
        }

        return true;
    }
}
