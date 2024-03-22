// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../libraries/EdOnBN254.sol";
import "../libraries/Transcript.sol";
import "../verifier/ChaumPedersenDLVerifier.sol";
import "../verifier/Groth16Verifier.sol";

struct MaskedCard {
    uint256 e2X;
    uint256 e2Y;
    uint256 e1X;
    uint256 e1Y;
}

contract RevealVerifier is Groth16Verifier {
    function aggregateKeys(EdOnBN254.Point[] memory pks) public view returns (EdOnBN254.Point memory) {
        EdOnBN254.Point memory joint = pks[0];
        for (uint i = 1; i < pks.length; i++) {
            joint = EdOnBN254.add(joint, pks[i]);
        }
        return joint;
    }

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
        ChuamPerdensenDLParameters memory parameters = ChuamPerdensenDLParameters(
            EdOnBN254.Point(masked.e1X, masked.e1Y),
            EdOnBN254.generator()
        );

        return ChuamPerdensenDLVerifier.verify(parameters, "Revealing", reveal, pk, proof);
    }

    function verifyRevealWithSnark(
        uint256[7] calldata _pi, // _pi = [mask.e1.x, mask.e1.y, reveal.x, reveal.y, pk.x, pk.y, challenge]
        uint256[5] calldata _proof,
        uint256[8] calldata _zkproof // _zkproof = [a, b, c]
    ) public view returns (bool) {
        assembly {
            mstore(mload(0x40), 0x52657665616c696e67)
            mstore(add(mload(0x40), 0x20), 0x444c)
            mstore(add(mload(0x40), 0x40), calldataload(_pi))
            mstore(add(mload(0x40), 0x60), calldataload(add(_pi, 0x20)))
            mstore(
                add(mload(0x40), 0x80),
                19698561148652590122159747500897617769866003486955115824547446575314762165298
            )
            mstore(
                add(mload(0x40), 0xa0),
                19298250018296453272277890825869354524455968081175474282777126169995084727839
            )
            mstore(add(mload(0x40), 0xc0), calldataload(add(_pi, 0x40)))
            mstore(add(mload(0x40), 0xe0), calldataload(add(_pi, 0x60)))
            mstore(add(mload(0x40), 0x100), calldataload(add(_pi, 0x80)))
            mstore(add(mload(0x40), 0x120), calldataload(add(_pi, 0xa0)))
            mstore(add(mload(0x40), 0x140), calldataload(_proof))
            mstore(add(mload(0x40), 0x160), calldataload(add(_proof, 0x20)))
            mstore(add(mload(0x40), 0x180), calldataload(add(_proof, 0x40)))
            mstore(add(mload(0x40), 0x1a0), calldataload(add(_proof, 0x60)))
            let r := mod(
                keccak256(mload(0x40), 0x1c0),
                2736030358979909402780800718157159386076813972158567259200215660948447373041
            )
            switch eq(r, calldataload(add(_pi, 0xc0)))
            case 0 {
                mstore(0, 0)
                return(0, 0x20)
            }
            case 1 {

            }
            default {
                mstore(0, 0)
                return(0, 0x20)
            }
        }

        return verifyProof(_zkproof, _pi);
    }

    function unmask(
        MaskedCard memory masked,
        EdOnBN254.Point[] memory reveals
    ) public view returns (EdOnBN254.Point memory) {
        EdOnBN254.Point memory aggregate = reveals[0];
        for (uint i = 1; i < reveals.length; i++) {
            aggregate = EdOnBN254.add(aggregate, reveals[i]);
        }
        return EdOnBN254.add(EdOnBN254.Point(masked.e2X, masked.e2Y), EdOnBN254.neg(aggregate));
    }
}
