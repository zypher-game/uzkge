// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../verifier/PlonkVerifier.sol";
import "./VerifierKey.sol";
import "./ExternalTranscript.sol";

contract ShuffleVerifier is PlonkVerifier {
    uint256 public constant PKC_LEN = 24;

    address vk1;
    address vk2;
    uint256 deckNum;

    uint256[] private deck;
    uint256[] private pkc;

    constructor(address _vk1, address _vk2, uint256 _deckNum) {
        vk1 = _vk1;
        vk2 = _vk2;
        deckNum = _deckNum;
    }

    function setPkc(uint256[] calldata _pkc) public {
        require(_pkc.length == PKC_LEN, "PV02");
        pkc = _pkc;
    }

    function setDeck(uint256[] calldata _deck) public {
        require(_deck.length == deckNum * 4, "PV03");
        deck = _deck;
    }

    function verify(uint256[] calldata newDeck, bytes calldata proof) public view {
        uint256 deckLength = deckNum * 4;
        require(newDeck.length == deckLength, "PV01");

        uint256[] memory pi = new uint256[](deckLength * 2);
        for (uint256 i = 0; i < deckLength; i++) {
            pi[i] = deck[i];
            pi[i + deckLength] = newDeck[i];
        }

        uint256[] memory pc = new uint256[](PKC_LEN);
        for (uint256 i = 0; i < pkc.length; i++) {
            pc[i] = pkc[i];
        }

        require(this.verifyShuffle(proof, pi, pc), "PV00");
    }

    function verifyShuffle(
        bytes calldata _proof,
        uint256[] calldata _publicKeyInput,
        uint256[] calldata _publicKeyCommitment
    ) public view returns (bool) {
        VerifierKey.load(CM_Q0_X_LOC, PI_POLY_RELATED_LOC);
        ExternalTranscript.load(EXTERNAL_TRANSCRIPT_LENGTH_LOC);

        // The scalar field of BN254.
        uint256 r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        // Load the proof.
        assembly {
            let data_ptr := add(calldataload(0x04), 0x24)
            mstore(CM_W0_X_LOC, mod(calldataload(add(data_ptr, 0x00)), r))
            mstore(CM_W0_Y_LOC, mod(calldataload(add(data_ptr, 0x20)), r))
            mstore(CM_W1_X_LOC, mod(calldataload(add(data_ptr, 0x40)), r))
            mstore(CM_W1_Y_LOC, mod(calldataload(add(data_ptr, 0x60)), r))
            mstore(CM_W2_X_LOC, mod(calldataload(add(data_ptr, 0x80)), r))
            mstore(CM_W2_Y_LOC, mod(calldataload(add(data_ptr, 0xa0)), r))
            mstore(CM_W3_X_LOC, mod(calldataload(add(data_ptr, 0xc0)), r))
            mstore(CM_W3_Y_LOC, mod(calldataload(add(data_ptr, 0xe0)), r))
            mstore(CM_W4_X_LOC, mod(calldataload(add(data_ptr, 0x100)), r))
            mstore(CM_W4_Y_LOC, mod(calldataload(add(data_ptr, 0x120)), r))
            mstore(CM_W0_SEL_X_LOC, mod(calldataload(add(data_ptr, 0x140)), r))
            mstore(CM_W0_SEL_Y_LOC, mod(calldataload(add(data_ptr, 0x160)), r))
            mstore(CM_W1_SEL_X_LOC, mod(calldataload(add(data_ptr, 0x180)), r))
            mstore(CM_W1_SEL_Y_LOC, mod(calldataload(add(data_ptr, 0x1a0)), r))
            mstore(CM_W2_SEL_X_LOC, mod(calldataload(add(data_ptr, 0x1c0)), r))
            mstore(CM_W2_SEL_Y_LOC, mod(calldataload(add(data_ptr, 0x1e0)), r))
            mstore(CM_T0_X_LOC, mod(calldataload(add(data_ptr, 0x200)), r))
            mstore(CM_T0_Y_LOC, mod(calldataload(add(data_ptr, 0x220)), r))
            mstore(CM_T1_X_LOC, mod(calldataload(add(data_ptr, 0x240)), r))
            mstore(CM_T1_Y_LOC, mod(calldataload(add(data_ptr, 0x260)), r))
            mstore(CM_T2_X_LOC, mod(calldataload(add(data_ptr, 0x280)), r))
            mstore(CM_T2_Y_LOC, mod(calldataload(add(data_ptr, 0x2a0)), r))
            mstore(CM_T3_X_LOC, mod(calldataload(add(data_ptr, 0x2c0)), r))
            mstore(CM_T3_Y_LOC, mod(calldataload(add(data_ptr, 0x2e0)), r))
            mstore(CM_T4_X_LOC, mod(calldataload(add(data_ptr, 0x300)), r))
            mstore(CM_T4_Y_LOC, mod(calldataload(add(data_ptr, 0x320)), r))
            mstore(CM_Z_X_LOC, mod(calldataload(add(data_ptr, 0x340)), r))
            mstore(CM_Z_Y_LOC, mod(calldataload(add(data_ptr, 0x360)), r))
            mstore(PRK_3_EVAL_ZETA_LOC, mod(calldataload(add(data_ptr, 0x380)), r))
            mstore(PRK_4_EVAL_ZETA_LOC, mod(calldataload(add(data_ptr, 0x3a0)), r))
            mstore(W_POLY_EVAL_ZETA_0_LOC, mod(calldataload(add(data_ptr, 0x3c0)), r))
            mstore(W_POLY_EVAL_ZETA_1_LOC, mod(calldataload(add(data_ptr, 0x3e0)), r))
            mstore(W_POLY_EVAL_ZETA_2_LOC, mod(calldataload(add(data_ptr, 0x400)), r))
            mstore(W_POLY_EVAL_ZETA_3_LOC, mod(calldataload(add(data_ptr, 0x420)), r))
            mstore(W_POLY_EVAL_ZETA_4_LOC, mod(calldataload(add(data_ptr, 0x440)), r))
            mstore(W_POLY_EVAL_ZETA_OMEGA_0_LOC, mod(calldataload(add(data_ptr, 0x460)), r))
            mstore(W_POLY_EVAL_ZETA_OMEGA_1_LOC, mod(calldataload(add(data_ptr, 0x480)), r))
            mstore(W_POLY_EVAL_ZETA_OMEGA_2_LOC, mod(calldataload(add(data_ptr, 0x4a0)), r))
            mstore(Z_EVAL_ZETA_OMEGA_LOC, mod(calldataload(add(data_ptr, 0x4c0)), r))
            mstore(S_POLY_EVAL_ZETA_0_LOC, mod(calldataload(add(data_ptr, 0x4e0)), r))
            mstore(S_POLY_EVAL_ZETA_1_LOC, mod(calldataload(add(data_ptr, 0x500)), r))
            mstore(S_POLY_EVAL_ZETA_2_LOC, mod(calldataload(add(data_ptr, 0x520)), r))
            mstore(S_POLY_EVAL_ZETA_3_LOC, mod(calldataload(add(data_ptr, 0x540)), r))
            mstore(Q_ECC_POLY_EVAL_ZETA_LOC, mod(calldataload(add(data_ptr, 0x560)), r))
            mstore(W_SEL_POLY_EVAL_ZETA_0_LOC, mod(calldataload(add(data_ptr, 0x580)), r))
            mstore(W_SEL_POLY_EVAL_ZETA_1_LOC, mod(calldataload(add(data_ptr, 0x5a0)), r))
            mstore(W_SEL_POLY_EVAL_ZETA_2_LOC, mod(calldataload(add(data_ptr, 0x5c0)), r))
            mstore(OPENING_ZETA_X_LOC, mod(calldataload(add(data_ptr, 0x5e0)), r))
            mstore(OPENING_ZETA_Y_LOC, mod(calldataload(add(data_ptr, 0x600)), r))
            mstore(OPENING_ZETA_OMEGA_X_LOC, mod(calldataload(add(data_ptr, 0x620)), r))
            mstore(OPENING_ZETA_OMEGA_Y_LOC, mod(calldataload(add(data_ptr, 0x640)), r))
        }

        // Load the public inputs.
        assembly {
            let pi_ptr := add(calldataload(0x24), 0x04)
            let pi_length := calldataload(add(pi_ptr, 0x00))
            let store_ptr := add(PI_POLY_RELATED_LOC, 0x20)

            for {
                let i := 0
            } lt(i, pi_length) {
                i := add(i, 1)
            } {
                mstore(add(store_ptr, mul(i, 0x20)), calldataload(add(add(pi_ptr, 0x20), mul(i, 0x20))))
            }
        }

        // Load the public key commitment.
        assembly {
            let pk_ptr := add(calldataload(0x44), 0x24)
            mstore(CM_SHUFFLE_PUBLIC_KEY_0_X_LOC, mod(calldataload(add(pk_ptr, 0x00)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_0_Y_LOC, mod(calldataload(add(pk_ptr, 0x20)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_1_X_LOC, mod(calldataload(add(pk_ptr, 0x40)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_1_Y_LOC, mod(calldataload(add(pk_ptr, 0x60)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_2_X_LOC, mod(calldataload(add(pk_ptr, 0x80)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_2_Y_LOC, mod(calldataload(add(pk_ptr, 0xa0)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_3_X_LOC, mod(calldataload(add(pk_ptr, 0xc0)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_3_Y_LOC, mod(calldataload(add(pk_ptr, 0xe0)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_4_X_LOC, mod(calldataload(add(pk_ptr, 0x100)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_4_Y_LOC, mod(calldataload(add(pk_ptr, 0x120)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_5_X_LOC, mod(calldataload(add(pk_ptr, 0x140)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_5_Y_LOC, mod(calldataload(add(pk_ptr, 0x160)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_6_X_LOC, mod(calldataload(add(pk_ptr, 0x180)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_6_Y_LOC, mod(calldataload(add(pk_ptr, 0x1a0)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_7_X_LOC, mod(calldataload(add(pk_ptr, 0x1c0)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_7_Y_LOC, mod(calldataload(add(pk_ptr, 0x1e0)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_8_X_LOC, mod(calldataload(add(pk_ptr, 0x200)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_8_Y_LOC, mod(calldataload(add(pk_ptr, 0x220)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_9_X_LOC, mod(calldataload(add(pk_ptr, 0x240)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_9_Y_LOC, mod(calldataload(add(pk_ptr, 0x260)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_10_X_LOC, mod(calldataload(add(pk_ptr, 0x280)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_10_Y_LOC, mod(calldataload(add(pk_ptr, 0x2a0)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_11_X_LOC, mod(calldataload(add(pk_ptr, 0x2c0)), r))
            mstore(CM_SHUFFLE_PUBLIC_KEY_11_Y_LOC, mod(calldataload(add(pk_ptr, 0x2e0)), r))
        }

        return verifyShuffleProof(vk1, vk2);
    }
}
