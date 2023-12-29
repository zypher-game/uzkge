// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "./EdOnBN254.sol";
import "./Transcript.sol";

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
        bytes[] memory externalInputTranscript,
        EdOnBN254.Point memory c1,
        EdOnBN254.Point memory c2,
        ChuamPerdensenDLProof memory proof
    ) internal view returns (bool) {
        Transcript.TranscriptData memory transcript;

        for (uint i = 0; i < externalInputTranscript.length; i++) {
            transcript.appendMessage(externalInputTranscript[i]);
        }

        // init transcript
        transcript.appendMessage("DL");
        transcript.appendCommitmentEdOnBN254(parameters.g);
        transcript.appendCommitmentEdOnBN254(parameters.h);
        transcript.appendCommitmentEdOnBN254(c1);
        transcript.appendCommitmentEdOnBN254(c2);
        transcript.appendCommitmentEdOnBN254(proof.a);
        transcript.appendCommitmentEdOnBN254(proof.b);

        uint256 c = transcript.getAndAppendChallenge();

        EdOnBN254.Point memory r1Left = EdOnBN254.scalarMul(parameters.g, proof.r);
        EdOnBN254.Point memory r1Right = EdOnBN254.add(proof.a, EdOnBN254.scalarMul(c1, c));
        if (r1Left.x != r1Right.x || r1Left.y != r1Right.y) {
            return false;
        }

        EdOnBN254.Point memory r2Left = EdOnBN254.scalarMul(parameters.h, proof.r);
        EdOnBN254.Point memory r2Right = EdOnBN254.add(proof.b, EdOnBN254.scalarMul(c2, c));
        if (r2Left.x != r2Right.x || r2Left.y != r2Right.y) {
            return false;
        }

        return true;
    }
}
