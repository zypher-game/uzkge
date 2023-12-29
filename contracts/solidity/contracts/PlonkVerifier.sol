// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "hardhat/console.sol";

contract PlonkVerifier {
    // The proof memory locations.
    uint256 internal constant CM_W0_X_LOC = 0x200 + 0x00;
    uint256 internal constant CM_W0_Y_LOC = 0x200 + 0x20;
    uint256 internal constant CM_W1_X_LOC = 0x200 + 0x40;
    uint256 internal constant CM_W1_Y_LOC = 0x200 + 0x60;
    uint256 internal constant CM_W2_X_LOC = 0x200 + 0x80;
    uint256 internal constant CM_W2_Y_LOC = 0x200 + 0xa0;
    uint256 internal constant CM_W3_X_LOC = 0x200 + 0xc0;
    uint256 internal constant CM_W3_Y_LOC = 0x200 + 0xe0;
    uint256 internal constant CM_W4_X_LOC = 0x200 + 0x100;
    uint256 internal constant CM_W4_Y_LOC = 0x200 + 0x120;
    uint256 internal constant CM_T0_X_LOC = 0x200 + 0x140;
    uint256 internal constant CM_T0_Y_LOC = 0x200 + 0x160;
    uint256 internal constant CM_T1_X_LOC = 0x200 + 0x180;
    uint256 internal constant CM_T1_Y_LOC = 0x200 + 0x1a0;
    uint256 internal constant CM_T2_X_LOC = 0x200 + 0x1c0;
    uint256 internal constant CM_T2_Y_LOC = 0x200 + 0x1e0;
    uint256 internal constant CM_T3_X_LOC = 0x200 + 0x200;
    uint256 internal constant CM_T3_Y_LOC = 0x200 + 0x220;
    uint256 internal constant CM_T4_X_LOC = 0x200 + 0x240;
    uint256 internal constant CM_T4_Y_LOC = 0x200 + 0x260;
    uint256 internal constant CM_Z_X_LOC = 0x200 + 0x280;
    uint256 internal constant CM_Z_Y_LOC = 0x200 + 0x2a0;
    uint256 internal constant PRK_3_EVAL_ZAETA_LOC = 0x200 + 0x2c0;
    uint256 internal constant PRK_4_EVAL_ZAETA_LOC = 0x200 + 0x2e0;
    uint256 internal constant W_POLY_EVAL_ZAETA_0_LOC = 0x200 + 0x300;
    uint256 internal constant W_POLY_EVAL_ZAETA_1_LOC = 0x200 + 0x320;
    uint256 internal constant W_POLY_EVAL_ZAETA_2_LOC = 0x200 + 0x340;
    uint256 internal constant W_POLY_EVAL_ZAETA_3_LOC = 0x200 + 0x360;
    uint256 internal constant W_POLY_EVAL_ZAETA_4_LOC = 0x200 + 0x380;
    uint256 internal constant W_POLY_EVAL_ZAETA_OMEGA_0_LOC = 0x200 + 0x3a0;
    uint256 internal constant W_POLY_EVAL_ZAETA_OMEGA_1_LOC = 0x200 + 0x3c0;
    uint256 internal constant W_POLY_EVAL_ZAETA_OMEGA_2_LOC = 0x200 + 0x3e0;
    uint256 internal constant Z_EVAL_ZETA_OMEGA_LOC = 0x200 + 0x400;
    uint256 internal constant S_POLY_EVAL_ZAETA_0_LOC = 0x200 + 0x420;
    uint256 internal constant S_POLY_EVAL_ZAETA_1_LOC = 0x200 + 0x440;
    uint256 internal constant S_POLY_EVAL_ZAETA_2_LOC = 0x200 + 0x460;
    uint256 internal constant S_POLY_EVAL_ZAETA_3_LOC = 0x200 + 0x480;
    uint256 internal constant OPENING_ZETA_X_LOC = 0x200 + 0x4a0;
    uint256 internal constant OPENING_ZETA_Y_LOC = 0x200 + 0x4c0;
    uint256 internal constant OPENING_ZETA_OMEGA_X_LOC = 0x200 + 0x4e0;
    uint256 internal constant OPENING_ZETA_OMEGA_Y_LOC = 0x200 + 0x500;

    // The challenge memory locations.
    uint256 internal constant ALPHA_LOC = 0x200 + 0x520;
    uint256 internal constant BETA_LOC = 0x200 + 0x540;
    uint256 internal constant GAMMA_LOC = 0x200 + 0x560;
    uint256 internal constant ZETA_LOC = 0x200 + 0x580;
    uint256 internal constant U_LOC = 0x200 + 0x5a0;
    uint256 internal constant ALPHA_POW_2_LOC = 0x200 + 0x5c0;
    uint256 internal constant ALPHA_POW_3_LOC = 0x200 + 0x5e0;
    uint256 internal constant ALPHA_POW_4_LOC = 0x200 + 0x600;
    uint256 internal constant ALPHA_POW_5_LOC = 0x200 + 0x620;
    uint256 internal constant ALPHA_POW_6_LOC = 0x200 + 0x640;
    uint256 internal constant ALPHA_POW_7_LOC = 0x200 + 0x660;
    uint256 internal constant ALPHA_POW_8_LOC = 0x200 + 0x680;
    uint256 internal constant ALPHA_POW_9_LOC = 0x200 + 0x6a0;
    uint256 internal constant ALPHA_BATCH_12_LOC = 0x200 + 0x6c0;
    uint256 internal constant ALPHA_BATCH_4_LOC = 0x200 + 0x6e0;

    // The verifier key memory locations
    uint256 internal constant CM_Q0_X_LOC = 0x200 + 0x700;
    uint256 internal constant CM_Q0_Y_LOC = 0x200 + 0x720;
    uint256 internal constant CM_Q1_X_LOC = 0x200 + 0x740;
    uint256 internal constant CM_Q1_Y_LOC = 0x200 + 0x760;
    uint256 internal constant CM_Q2_X_LOC = 0x200 + 0x780;
    uint256 internal constant CM_Q2_Y_LOC = 0x200 + 0x7a0;
    uint256 internal constant CM_Q3_X_LOC = 0x200 + 0x7c0;
    uint256 internal constant CM_Q3_Y_LOC = 0x200 + 0x7e0;
    uint256 internal constant CM_Q4_X_LOC = 0x200 + 0x800;
    uint256 internal constant CM_Q4_Y_LOC = 0x200 + 0x820;
    uint256 internal constant CM_Q5_X_LOC = 0x200 + 0x840;
    uint256 internal constant CM_Q5_Y_LOC = 0x200 + 0x860;
    uint256 internal constant CM_Q6_X_LOC = 0x200 + 0x880;
    uint256 internal constant CM_Q6_Y_LOC = 0x200 + 0x8a0;
    uint256 internal constant CM_Q7_X_LOC = 0x200 + 0x8c0;
    uint256 internal constant CM_Q7_Y_LOC = 0x200 + 0x8e0;
    uint256 internal constant CM_Q8_X_LOC = 0x200 + 0x900;
    uint256 internal constant CM_Q8_Y_LOC = 0x200 + 0x920;
    uint256 internal constant CM_S0_X_LOC = 0x200 + 0x940;
    uint256 internal constant CM_S0_Y_LOC = 0x200 + 0x960;
    uint256 internal constant CM_S1_X_LOC = 0x200 + 0x980;
    uint256 internal constant CM_S1_Y_LOC = 0x200 + 0x9a0;
    uint256 internal constant CM_S2_X_LOC = 0x200 + 0x9c0;
    uint256 internal constant CM_S2_Y_LOC = 0x200 + 0x9e0;
    uint256 internal constant CM_S3_X_LOC = 0x200 + 0xa00;
    uint256 internal constant CM_S3_Y_LOC = 0x200 + 0xa20;
    uint256 internal constant CM_S4_X_LOC = 0x200 + 0xa40;
    uint256 internal constant CM_S4_Y_LOC = 0x200 + 0xa60;
    uint256 internal constant CM_QB_X_LOC = 0x200 + 0xa80;
    uint256 internal constant CM_QB_Y_LOC = 0x200 + 0xaa0;
    uint256 internal constant CM_PRK_0_X_LOC = 0x200 + 0xac0;
    uint256 internal constant CM_PRK_0_Y_LOC = 0x200 + 0xae0;
    uint256 internal constant CM_PRK_1_X_LOC = 0x200 + 0xb00;
    uint256 internal constant CM_PRK_1_Y_LOC = 0x200 + 0xb20;
    uint256 internal constant CM_PRK_2_X_LOC = 0x200 + 0xb40;
    uint256 internal constant CM_PRK_2_Y_LOC = 0x200 + 0xb60;
    uint256 internal constant CM_PRK_3_X_LOC = 0x200 + 0xb80;
    uint256 internal constant CM_PRK_3_Y_LOC = 0x200 + 0xba0;
    uint256 internal constant ANEMOI_GENERATOR_LOC = 0x200 + 0xbc0;
    uint256 internal constant ANEMOI_GENERATOR_INV_LOC = 0x200 + 0xbe0;
    uint256 internal constant K_0_LOC = 0x200 + 0xc00;
    uint256 internal constant K_1_LOC = 0x200 + 0xc20;
    uint256 internal constant K_2_LOC = 0x200 + 0xc40;
    uint256 internal constant K_3_LOC = 0x200 + 0xc60;
    uint256 internal constant K_4_LOC = 0x200 + 0xc80;
    uint256 internal constant ROOT_LOC = 0x200 + 0xca0;
    uint256 internal constant CS_SIZE_LOC = 0x200 + 0xcc0;

    // The intermediary variable memory locations.
    uint256 internal constant Z_H_EVAL_ZETA_LOC = 0x200 + 0xce0;
    uint256 internal constant FIRST_LAGRANGE_EVAL_ZETA_LOC = 0x200 + 0xd00;
    uint256 internal constant PI_EVAL_ZETA_LOC = 0x200 + 0xd20;
    uint256 internal constant W3_W0_LOC = 0x200 + 0xd40;
    uint256 internal constant W2_W1_LOC = 0x200 + 0xd60;
    uint256 internal constant W3_2W0_LOC = 0x200 + 0xd80;
    uint256 internal constant W2_2W1_LOC = 0x200 + 0xda0;
    uint256 internal constant R_EVAL_ZETA_LOC = 0x200 + 0xdc0;
    uint256 internal constant R_COMMITMENT_X_LOC = 0x200 + 0xde0;
    uint256 internal constant R_COMMITMENT_Y_LOC = 0x200 + 0xe00;
    uint256 internal constant COMMITMENT_X_LOC = 0x200 + 0xe20;
    uint256 internal constant COMMITMENT_Y_LOC = 0x200 + 0xe40;
    uint256 internal constant VALUE_LOC = 0x200 + 0xe60;
    uint256 internal constant BATCH_COMMITMENT_X_LOC = 0x200 + 0xe80;
    uint256 internal constant BATCH_COMMITMENT_Y_LOC = 0x200 + 0xea0;
    uint256 internal constant BATCH_VALUE_LOC = 0x200 + 0xec0;
    uint256 internal constant SUCCESS_LOC = 0x200 + 0xee0;

    // We reserve 20 slots for external input TRANSCRIPT,
    // so the length of the external input TRANSCRIPT cannot exceed 20.
    uint256 internal constant EXTERNAL_TRANSCRIPT_LENGTH_LOC = 0x200 + 0xf00;

    // The first slot represents the length of pulic inputs，
    // the next slot for the length of pulic inputs represents the public constrain variables indices(power format)，
    // the following slot for the length of pulic inputs represents the constrain lagrange base by public constrain variables.
    // and the following slot for the length of pulic inputs represents the constrain lagrange base by public inputs.
    uint256 internal constant PI_POLY_RELATED_LOC = 0x200 + 0x11a0;

    function verify_proof() public view returns (bool) {
        assembly {
            // The scalar field of BN254.
            let
                r
            := 21888242871839275222246405745257275088548364400416034343698204186575808495617

            mstore(
                0x40,
                add(mul(mload(PI_POLY_RELATED_LOC), 0x60), add(0x200, 0x11c0))
            )

            mstore(mload(SUCCESS_LOC), true)

            // Rerutn the invert of the value.
            function invert(fr) -> result {
                mstore(mload(0x40), 0x20)
                mstore(add(mload(0x40), 0x20), 0x20)
                mstore(add(mload(0x40), 0x40), 0x20)
                mstore(add(mload(0x40), 0x60), fr)
                mstore(
                    add(mload(0x40), 0x80),
                    sub(
                        21888242871839275222246405745257275088548364400416034343698204186575808495617,
                        2
                    )
                )
                mstore(
                    add(mload(0x40), 0xa0),
                    21888242871839275222246405745257275088548364400416034343698204186575808495617
                )

                let success_flag := staticcall(
                    gas(),
                    0x05,
                    mload(0x40),
                    0xc0,
                    mload(0x40),
                    0x20
                )
                mstore(
                    mload(SUCCESS_LOC),
                    and(mload(mload(SUCCESS_LOC)), success_flag)
                )

                result := mload(mload(0x40))
            }

            // Batch invert values in memory[mload(0x40)..mptr_end] in place.
            function batch_invert(end_ptr) {
                let prod_ptr := add(end_ptr, 0x20)
                let tmp := mload(mload(0x40))
                mstore(prod_ptr, tmp)
                for {
                    let i := add(mload(0x40), 0x20)
                } lt(i, add(end_ptr, 0x01)) {
                    i := add(i, 0x20)
                } {
                    tmp := mulmod(
                        tmp,
                        mload(i),
                        21888242871839275222246405745257275088548364400416034343698204186575808495617
                    )
                    prod_ptr := add(prod_ptr, 0x20)
                    mstore(prod_ptr, tmp)
                }

                mstore(add(prod_ptr, 0x20), 0x20)
                mstore(add(prod_ptr, 0x40), 0x20)
                mstore(add(prod_ptr, 0x60), 0x20)
                mstore(add(prod_ptr, 0x80), tmp)
                mstore(
                    add(prod_ptr, 0xa0),
                    sub(
                        21888242871839275222246405745257275088548364400416034343698204186575808495617,
                        2
                    )
                )
                mstore(
                    add(prod_ptr, 0xc0),
                    21888242871839275222246405745257275088548364400416034343698204186575808495617
                )
                let success_flag := staticcall(
                    gas(),
                    0x05,
                    add(prod_ptr, 0x20),
                    0xc0,
                    add(prod_ptr, 0x20),
                    0x20
                )
                mstore(
                    mload(SUCCESS_LOC),
                    and(mload(mload(SUCCESS_LOC)), success_flag)
                )

                let all_inv := mload(add(prod_ptr, 0x20))

                prod_ptr := sub(prod_ptr, 0x20)
                for {

                } lt(mload(0x40), end_ptr) {

                } {
                    let inv := mulmod(
                        all_inv,
                        mload(prod_ptr),
                        21888242871839275222246405745257275088548364400416034343698204186575808495617
                    )
                    all_inv := mulmod(
                        all_inv,
                        mload(end_ptr),
                        21888242871839275222246405745257275088548364400416034343698204186575808495617
                    )
                    mstore(end_ptr, inv)
                    prod_ptr := sub(prod_ptr, 0x20)
                    end_ptr := sub(end_ptr, 0x20)
                }

                mstore(mload(0x40), all_inv)
            }

            // Return base^exponent (mod modulus)
            function pow_small(base, exponent) -> result {
                result := 1
                let input := base
                for {
                    let count := 1
                } lt(count, add(exponent, 0x01)) {
                    count := add(count, count)
                } {
                    if and(exponent, count) {
                        result := mulmod(
                            result,
                            input,
                            21888242871839275222246405745257275088548364400416034343698204186575808495617
                        )
                    }
                    input := mulmod(
                        input,
                        input,
                        21888242871839275222246405745257275088548364400416034343698204186575808495617
                    )
                }
            }

            // Scale point by scalar.
            function scalar_mul(x, y, scalar) {
                mstore(mload(0x40), x)
                mstore(add(mload(0x40), 0x20), y)
                mstore(add(mload(0x40), 0x40), scalar)
                let success_flag := staticcall(
                    gas(),
                    7,
                    mload(0x40),
                    0x60,
                    mload(0x40),
                    0x40
                )
                mstore(
                    mload(SUCCESS_LOC),
                    and(mload(mload(SUCCESS_LOC)), success_flag)
                )
            }

            // Add point into point.
            function point_add(x0, y0, x1, y1) {
                mstore(mload(0x40), x0)
                mstore(add(mload(0x40), 0x20), y0)
                mstore(add(mload(0x40), 0x40), x1)
                mstore(add(mload(0x40), 0x60), y1)
                let success_flag := staticcall(
                    gas(),
                    6,
                    mload(0x40),
                    0x80,
                    mload(0x40),
                    0x40
                )
                mstore(
                    mload(SUCCESS_LOC),
                    and(mload(mload(SUCCESS_LOC)), success_flag)
                )
            }

            // Add point(x,y) into point at (mload(0x40), add(mload(0x40),0x20)).
            function point_add_in_memory(x, y) {
                mstore(add(mload(0x40), 0x40), x)
                mstore(add(mload(0x40), 0x60), y)
                let success_flag := staticcall(
                    gas(),
                    6,
                    mload(0x40),
                    0x80,
                    mload(0x40),
                    0x40
                )
                mstore(
                    mload(SUCCESS_LOC),
                    and(mload(mload(SUCCESS_LOC)), success_flag)
                )
            }

            // 1. compute all challenges.
            {
                let external_transcript_length := mload(
                    EXTERNAL_TRANSCRIPT_LENGTH_LOC
                )

                for {
                    let i := 0
                } lt(i, external_transcript_length) {
                    i := add(i, 1)
                } {
                    mstore(
                        add(mload(0x40), mul(i, 0x20)),
                        mload(
                            add(
                                add(EXTERNAL_TRANSCRIPT_LENGTH_LOC, 0x20),
                                mul(i, 0x20)
                            )
                        )
                    )
                }

                let ptr := add(
                    mload(0x40),
                    mul(external_transcript_length, 0x20)
                )
                mstore(ptr, 0x504c4f4e4b)
                mstore(add(ptr, 0x20), mload(CS_SIZE_LOC))
                mstore(add(ptr, 0x40), r)

                mstore(add(ptr, 0x60), mload(CM_Q0_X_LOC))
                mstore(add(ptr, 0x80), mload(CM_Q0_Y_LOC))

                mstore(add(ptr, 0xa0), mload(CM_Q1_X_LOC))
                mstore(add(ptr, 0xc0), mload(CM_Q1_Y_LOC))

                mstore(add(ptr, 0xe0), mload(CM_Q2_X_LOC))
                mstore(add(ptr, 0x100), mload(CM_Q2_Y_LOC))

                mstore(add(ptr, 0x120), mload(CM_Q3_X_LOC))
                mstore(add(ptr, 0x140), mload(CM_Q3_Y_LOC))

                mstore(add(ptr, 0x160), mload(CM_Q4_X_LOC))
                mstore(add(ptr, 0x180), mload(CM_Q4_Y_LOC))

                mstore(add(ptr, 0x1a0), mload(CM_Q5_X_LOC))
                mstore(add(ptr, 0x1c0), mload(CM_Q5_Y_LOC))

                mstore(add(ptr, 0x1e0), mload(CM_Q6_X_LOC))
                mstore(add(ptr, 0x200), mload(CM_Q6_Y_LOC))

                mstore(add(ptr, 0x220), mload(CM_Q7_X_LOC))
                mstore(add(ptr, 0x240), mload(CM_Q7_Y_LOC))

                mstore(add(ptr, 0x260), mload(CM_Q8_X_LOC))
                mstore(add(ptr, 0x280), mload(CM_Q8_Y_LOC))

                mstore(add(ptr, 0x2a0), mload(CM_S0_X_LOC))
                mstore(add(ptr, 0x2c0), mload(CM_S0_Y_LOC))

                mstore(add(ptr, 0x2e0), mload(CM_S1_X_LOC))
                mstore(add(ptr, 0x300), mload(CM_S1_Y_LOC))

                mstore(add(ptr, 0x320), mload(CM_S2_X_LOC))
                mstore(add(ptr, 0x340), mload(CM_S2_Y_LOC))

                mstore(add(ptr, 0x360), mload(CM_S3_X_LOC))
                mstore(add(ptr, 0x380), mload(CM_S3_Y_LOC))

                mstore(add(ptr, 0x3a0), mload(CM_S4_X_LOC))
                mstore(add(ptr, 0x3c0), mload(CM_S4_Y_LOC))

                mstore(add(ptr, 0x3e0), mload(ROOT_LOC))

                mstore(add(ptr, 0x400), mload(K_0_LOC))
                mstore(add(ptr, 0x420), mload(K_1_LOC))
                mstore(add(ptr, 0x440), mload(K_2_LOC))
                mstore(add(ptr, 0x460), mload(K_3_LOC))
                mstore(add(ptr, 0x480), mload(K_4_LOC))

                let pi_length := mload(PI_POLY_RELATED_LOC)
                let pi_ptr := add(
                    mul(mload(PI_POLY_RELATED_LOC), 0x40),
                    add(PI_POLY_RELATED_LOC, 0x20)
                )
                for {
                    let i := 0
                } lt(i, pi_length) {
                    i := add(i, 1)
                } {
                    mstore(
                        add(add(ptr, 0x4a0), mul(i, 0x20)),
                        mload(add(pi_ptr, mul(i, 0x20)))
                    )
                }

                ptr := add(add(ptr, 0x4a0), mul(pi_length, 0x20))

                mstore(ptr, mload(CM_W0_X_LOC))
                mstore(add(ptr, 0x20), mload(CM_W0_Y_LOC))

                mstore(add(ptr, 0x40), mload(CM_W1_X_LOC))
                mstore(add(ptr, 0x60), mload(CM_W1_Y_LOC))

                mstore(add(ptr, 0x80), mload(CM_W2_X_LOC))
                mstore(add(ptr, 0xa0), mload(CM_W2_Y_LOC))

                mstore(add(ptr, 0xc0), mload(CM_W3_X_LOC))
                mstore(add(ptr, 0xe0), mload(CM_W3_Y_LOC))

                mstore(add(ptr, 0x100), mload(CM_W4_X_LOC))
                mstore(add(ptr, 0x120), mload(CM_W4_Y_LOC))

                // compute beta challenge.
                let beta := mod(
                    keccak256(
                        mload(0x40),
                        add(
                            add(
                                mul(external_transcript_length, 0x20),
                                mul(pi_length, 0x20)
                            ),
                            0x5e0
                        )
                    ),
                    r
                )
                mstore(BETA_LOC, beta)
                mstore(mload(0x40), beta)

                // compute gamma challenge.
                {
                    mstore8(add(mload(0x40), 0x20), 0x01)
                    let gamma := mod(keccak256(mload(0x40), 0x21), r)
                    mstore(GAMMA_LOC, gamma)
                    mstore(mload(0x40), gamma)
                }

                // compute alpha challenge.
                {
                    mstore(add(mload(0x40), 0x20), mload(CM_Z_X_LOC))
                    mstore(add(mload(0x40), 0x40), mload(CM_Z_Y_LOC))
                    let alpha := mod(keccak256(mload(0x40), 0x60), r)
                    mstore(ALPHA_LOC, alpha)
                    mstore(mload(0x40), alpha)
                }

                // compute zeta challenge.
                {
                    mstore(add(mload(0x40), 0x20), mload(CM_T0_X_LOC))
                    mstore(add(mload(0x40), 0x40), mload(CM_T0_Y_LOC))
                    mstore(add(mload(0x40), 0x60), mload(CM_T1_X_LOC))
                    mstore(add(mload(0x40), 0x80), mload(CM_T1_Y_LOC))
                    mstore(add(mload(0x40), 0xa0), mload(CM_T2_X_LOC))
                    mstore(add(mload(0x40), 0xc0), mload(CM_T2_Y_LOC))
                    mstore(add(mload(0x40), 0xe0), mload(CM_T3_X_LOC))
                    mstore(add(mload(0x40), 0x100), mload(CM_T3_Y_LOC))
                    mstore(add(mload(0x40), 0x120), mload(CM_T4_X_LOC))
                    mstore(add(mload(0x40), 0x140), mload(CM_T4_Y_LOC))
                    let zeta := mod(keccak256(mload(0x40), 0x160), r)
                    mstore(ZETA_LOC, zeta)
                    mstore(mload(0x40), zeta)
                }

                // compute u challenge.
                {
                    mstore(
                        add(mload(0x40), 0x20),
                        mload(W_POLY_EVAL_ZAETA_0_LOC)
                    )
                    mstore(
                        add(mload(0x40), 0x40),
                        mload(W_POLY_EVAL_ZAETA_1_LOC)
                    )
                    mstore(
                        add(mload(0x40), 0x60),
                        mload(W_POLY_EVAL_ZAETA_2_LOC)
                    )
                    mstore(
                        add(mload(0x40), 0x80),
                        mload(W_POLY_EVAL_ZAETA_3_LOC)
                    )
                    mstore(
                        add(mload(0x40), 0xa0),
                        mload(W_POLY_EVAL_ZAETA_4_LOC)
                    )
                    mstore(
                        add(mload(0x40), 0xc0),
                        mload(S_POLY_EVAL_ZAETA_0_LOC)
                    )
                    mstore(
                        add(mload(0x40), 0xe0),
                        mload(S_POLY_EVAL_ZAETA_1_LOC)
                    )
                    mstore(
                        add(mload(0x40), 0x100),
                        mload(S_POLY_EVAL_ZAETA_2_LOC)
                    )
                    mstore(
                        add(mload(0x40), 0x120),
                        mload(S_POLY_EVAL_ZAETA_3_LOC)
                    )
                    mstore(add(mload(0x40), 0x140), mload(PRK_3_EVAL_ZAETA_LOC))
                    mstore(add(mload(0x40), 0x160), mload(PRK_4_EVAL_ZAETA_LOC))
                    mstore(
                        add(mload(0x40), 0x180),
                        mload(Z_EVAL_ZETA_OMEGA_LOC)
                    )
                    mstore(
                        add(mload(0x40), 0x1a0),
                        mload(W_POLY_EVAL_ZAETA_OMEGA_0_LOC)
                    )
                    mstore(
                        add(mload(0x40), 0x1c0),
                        mload(W_POLY_EVAL_ZAETA_OMEGA_1_LOC)
                    )
                    mstore(
                        add(mload(0x40), 0x1e0),
                        mload(W_POLY_EVAL_ZAETA_OMEGA_2_LOC)
                    )
                    let u := mod(keccak256(mload(0x40), 0x200), r)
                    mstore(U_LOC, u)
                    mstore(mload(0x40), u)
                }

                {
                    mstore(
                        add(mload(0x40), 0x20),
                        0x4e6577205043532d42617463682d4576616c2050726f746f636f6c
                    )
                    mstore(add(mload(0x40), 0x40), r)
                    mstore(add(mload(0x40), 0x60), add(mload(CS_SIZE_LOC), 2))
                    mstore(add(mload(0x40), 0x80), mload(ZETA_LOC))
                    let alpha_batch_12 := mod(keccak256(mload(0x40), 0xa0), r)
                    mstore(ALPHA_BATCH_12_LOC, alpha_batch_12)
                    mstore(mload(0x40), alpha_batch_12)
                }

                {
                    mstore(
                        add(mload(0x40), 0x20),
                        0x4e6577205043532d42617463682d4576616c2050726f746f636f6c
                    )
                    mstore(add(mload(0x40), 0x40), r)
                    mstore(add(mload(0x40), 0x60), add(mload(CS_SIZE_LOC), 2))
                    let zeta_omega := mulmod(
                        mload(ZETA_LOC),
                        mload(ROOT_LOC),
                        r
                    )
                    mstore(add(mload(0x40), 0x80), zeta_omega)
                    let alpha_batch_4 := mod(keccak256(mload(0x40), 0xa0), r)
                    mstore(ALPHA_BATCH_4_LOC, alpha_batch_4)
                }

                {
                    let alpha := mload(ALPHA_LOC)
                    let alpha_pow_2 := mulmod(alpha, alpha, r)
                    let alpha_pow_3 := mulmod(alpha_pow_2, alpha, r)
                    let alpha_pow_4 := mulmod(alpha_pow_3, alpha, r)
                    let alpha_pow_5 := mulmod(alpha_pow_4, alpha, r)
                    let alpha_pow_6 := mulmod(alpha_pow_5, alpha, r)
                    let alpha_pow_7 := mulmod(alpha_pow_6, alpha, r)
                    let alpha_pow_8 := mulmod(alpha_pow_7, alpha, r)
                    let alpha_pow_9 := mulmod(alpha_pow_8, alpha, r)
                    mstore(ALPHA_POW_2_LOC, alpha_pow_2)
                    mstore(ALPHA_POW_3_LOC, alpha_pow_3)
                    mstore(ALPHA_POW_4_LOC, alpha_pow_4)
                    mstore(ALPHA_POW_5_LOC, alpha_pow_5)
                    mstore(ALPHA_POW_6_LOC, alpha_pow_6)
                    mstore(ALPHA_POW_7_LOC, alpha_pow_7)
                    mstore(ALPHA_POW_8_LOC, alpha_pow_8)
                    mstore(ALPHA_POW_9_LOC, alpha_pow_9)
                }
            }

            // 2. compute Z_h(\zeta) and L_1(\zeta).
            {
                let zeta := mload(ZETA_LOC)
                let zeta_power_n := pow_small(zeta, mload(CS_SIZE_LOC))
                let z_h_eval_zeta := addmod(zeta_power_n, sub(r, 1), r)

                let zeta_minus_one := addmod(zeta, sub(r, 1), r)
                let zeta_minus_one_inv := invert(zeta_minus_one)
                let first_lagrange_eval_zeta := mulmod(
                    z_h_eval_zeta,
                    zeta_minus_one_inv,
                    r
                )

                mstore(Z_H_EVAL_ZETA_LOC, z_h_eval_zeta)
                mstore(FIRST_LAGRANGE_EVAL_ZETA_LOC, first_lagrange_eval_zeta)
            }

            // 3. compute PI(\zeta).
            {
                let length := mload(PI_POLY_RELATED_LOC)
                let denominator_prod := 1
                let zeta := mload(ZETA_LOC)

                let end_ptr := mload(0x40)

                for {
                    let i := 0
                } lt(i, length) {
                    i := add(i, 1)
                } {
                    let root_pow := mload(
                        add(add(PI_POLY_RELATED_LOC, 0x20), mul(i, 0x20))
                    )
                    let denominator := addmod(zeta, sub(r, root_pow), r)
                    mstore(end_ptr, denominator)

                    end_ptr := add(end_ptr, 0x20)
                }

                batch_invert(end_ptr)

                let lagrange_constant_ptr := add(
                    add(PI_POLY_RELATED_LOC, 0x20),
                    mul(length, 0x20)
                )
                let pi_ptr := add(
                    mul(mload(PI_POLY_RELATED_LOC), 0x40),
                    add(PI_POLY_RELATED_LOC, 0x20)
                )
                let eval := 0
                for {
                    let i := 0
                } lt(i, length) {
                    i := add(i, 1)
                } {
                    let lagrange_constant := mload(
                        add(lagrange_constant_ptr, mul(i, 0x20))
                    )
                    let public_input := mload(add(pi_ptr, mul(i, 0x20)))

                    let tmp := mulmod(
                        mulmod(
                            lagrange_constant,
                            mload(add(mload(0x40), mul(i, 0x20))),
                            r
                        ),
                        public_input,
                        r
                    )

                    eval := addmod(tmp, eval, r)
                }

                eval := mulmod(eval, mload(Z_H_EVAL_ZETA_LOC), r)
                mstore(PI_EVAL_ZETA_LOC, eval)
            }

            // 4. derive the linearization polynomial commitment.
            {
                let res := sub(r, mload(PI_EVAL_ZETA_LOC))

                {
                    let term1 := mulmod(
                        mload(ALPHA_LOC),
                        mload(Z_EVAL_ZETA_OMEGA_LOC),
                        r
                    )

                    let beta := mload(BETA_LOC)
                    let gamma := mload(GAMMA_LOC)

                    let tmp := addmod(
                        addmod(mload(W_POLY_EVAL_ZAETA_0_LOC), gamma, r),
                        mulmod(beta, mload(S_POLY_EVAL_ZAETA_0_LOC), r),
                        r
                    )
                    term1 := mulmod(term1, tmp, r)

                    tmp := addmod(
                        addmod(mload(W_POLY_EVAL_ZAETA_1_LOC), gamma, r),
                        mulmod(beta, mload(S_POLY_EVAL_ZAETA_1_LOC), r),
                        r
                    )
                    term1 := mulmod(term1, tmp, r)

                    tmp := addmod(
                        addmod(mload(W_POLY_EVAL_ZAETA_2_LOC), gamma, r),
                        mulmod(beta, mload(S_POLY_EVAL_ZAETA_2_LOC), r),
                        r
                    )
                    term1 := mulmod(term1, tmp, r)

                    tmp := addmod(
                        addmod(mload(W_POLY_EVAL_ZAETA_3_LOC), gamma, r),
                        mulmod(beta, mload(S_POLY_EVAL_ZAETA_3_LOC), r),
                        r
                    )
                    term1 := mulmod(term1, tmp, r)

                    term1 := mulmod(
                        term1,
                        addmod(gamma, mload(W_POLY_EVAL_ZAETA_4_LOC), r),
                        r
                    )

                    res := addmod(res, term1, r)
                }

                {
                    let term2 := mulmod(
                        mload(FIRST_LAGRANGE_EVAL_ZETA_LOC),
                        mload(ALPHA_POW_2_LOC),
                        r
                    )

                    res := addmod(res, term2, r)
                }

                {
                    let anemoi_generator := mload(ANEMOI_GENERATOR_LOC)

                    let tmp
                    {
                        let w3_w0 := addmod(
                            mload(W_POLY_EVAL_ZAETA_3_LOC),
                            mload(W_POLY_EVAL_ZAETA_0_LOC),
                            r
                        )
                        let w2_w1 := addmod(
                            mload(W_POLY_EVAL_ZAETA_2_LOC),
                            mload(W_POLY_EVAL_ZAETA_1_LOC),
                            r
                        )
                        let w3_2w0 := addmod(
                            w3_w0,
                            mload(W_POLY_EVAL_ZAETA_0_LOC),
                            r
                        )
                        let w2_2w1 := addmod(
                            w2_w1,
                            mload(W_POLY_EVAL_ZAETA_1_LOC),
                            r
                        )
                        mstore(W3_W0_LOC, w2_w1)
                        mstore(W2_W1_LOC, w3_w0)
                        mstore(W3_2W0_LOC, w2_2w1)
                        mstore(W2_2W1_LOC, w3_2w0)

                        tmp := addmod(
                            addmod(w3_w0, mload(PRK_3_EVAL_ZAETA_LOC), r),
                            mulmod(w2_w1, anemoi_generator, r),
                            r
                        )
                    }

                    let tmp_sub_w2_polys_eval_zeta_omega_pow_5
                    {
                        let tmp_sub_w2_polys_eval_zeta_omega := addmod(
                            tmp,
                            sub(r, mload(W_POLY_EVAL_ZAETA_OMEGA_2_LOC)),
                            r
                        )
                        let tmp_sub_w2_polys_eval_zeta_omega_pow_2 := mulmod(
                            tmp_sub_w2_polys_eval_zeta_omega,
                            tmp_sub_w2_polys_eval_zeta_omega,
                            r
                        )
                        let tmp_sub_w2_polys_eval_zeta_omega_pow_4 := mulmod(
                            tmp_sub_w2_polys_eval_zeta_omega_pow_2,
                            tmp_sub_w2_polys_eval_zeta_omega_pow_2,
                            r
                        )
                        tmp_sub_w2_polys_eval_zeta_omega_pow_5 := mulmod(
                            tmp_sub_w2_polys_eval_zeta_omega,
                            tmp_sub_w2_polys_eval_zeta_omega_pow_4,
                            r
                        )
                    }

                    {
                        let term3 := addmod(
                            addmod(
                                tmp_sub_w2_polys_eval_zeta_omega_pow_5,
                                sub(
                                    r,
                                    addmod(
                                        mload(W2_2W1_LOC),
                                        mulmod(
                                            anemoi_generator,
                                            mload(W3_2W0_LOC),
                                            r
                                        ),
                                        r
                                    )
                                ),
                                r
                            ),
                            mulmod(anemoi_generator, mulmod(tmp, tmp, r), r),
                            r
                        )

                        term3 := mulmod(
                            term3,
                            mulmod(
                                mload(ALPHA_POW_6_LOC),
                                mload(PRK_3_EVAL_ZAETA_LOC),
                                r
                            ),
                            r
                        )

                        res := addmod(res, term3, r)
                    }

                    {
                        let w2_polys_eval_zeta_omega := mload(
                            W_POLY_EVAL_ZAETA_OMEGA_2_LOC
                        )
                        let w2_polys_eval_zeta_omega_square := mulmod(
                            w2_polys_eval_zeta_omega,
                            w2_polys_eval_zeta_omega,
                            r
                        )

                        let term5 := mulmod(
                            mload(ALPHA_POW_8_LOC),
                            mload(PRK_3_EVAL_ZAETA_LOC),
                            r
                        )

                        let term5_tmp := addmod(
                            addmod(
                                tmp_sub_w2_polys_eval_zeta_omega_pow_5,
                                mload(ANEMOI_GENERATOR_INV_LOC),
                                r
                            ),
                            mulmod(
                                anemoi_generator,
                                w2_polys_eval_zeta_omega_square,
                                r
                            ),
                            r
                        )
                        term5_tmp := addmod(
                            term5_tmp,
                            sub(r, mload(W_POLY_EVAL_ZAETA_OMEGA_0_LOC)),
                            r
                        )

                        term5 := mulmod(term5, term5_tmp, r)

                        res := addmod(res, term5, r)
                    }
                }

                {
                    let anemoi_generator := mload(ANEMOI_GENERATOR_LOC)
                    let anemoi_generator_square_plus_one := addmod(
                        1,
                        mulmod(anemoi_generator, anemoi_generator, r),
                        r
                    )

                    let tmp
                    let tmp_sub_w4_polys_eval_zeta_pow_5
                    {
                        tmp := addmod(
                            addmod(
                                mload(PRK_4_EVAL_ZAETA_LOC),
                                mulmod(
                                    anemoi_generator_square_plus_one,
                                    mload(W3_W0_LOC),
                                    r
                                ),
                                r
                            ),
                            mulmod(anemoi_generator, mload(W2_W1_LOC), r),
                            r
                        )
                        let tmp_sub_w4_polys_eval_zeta := addmod(
                            tmp,
                            sub(r, mload(W_POLY_EVAL_ZAETA_4_LOC)),
                            r
                        )
                        let tmp_sub_w4_polys_eval_zeta_pow_2 := mulmod(
                            tmp_sub_w4_polys_eval_zeta,
                            tmp_sub_w4_polys_eval_zeta,
                            r
                        )
                        let tmp_sub_w4_polys_eval_zeta_pow_4 := mulmod(
                            tmp_sub_w4_polys_eval_zeta_pow_2,
                            tmp_sub_w4_polys_eval_zeta_pow_2,
                            r
                        )
                        tmp_sub_w4_polys_eval_zeta_pow_5 := mulmod(
                            tmp_sub_w4_polys_eval_zeta,
                            tmp_sub_w4_polys_eval_zeta_pow_4,
                            r
                        )
                    }

                    {
                        let term4 := mulmod(
                            mload(ALPHA_POW_7_LOC),
                            mload(PRK_3_EVAL_ZAETA_LOC),
                            r
                        )

                        let term4_tmp := addmod(
                            addmod(
                                tmp_sub_w4_polys_eval_zeta_pow_5,
                                sub(
                                    r,
                                    addmod(
                                        mulmod(
                                            anemoi_generator,
                                            mload(W2_2W1_LOC),
                                            r
                                        ),
                                        mulmod(
                                            anemoi_generator_square_plus_one,
                                            mload(W3_2W0_LOC),
                                            r
                                        ),
                                        r
                                    )
                                ),
                                r
                            ),
                            mulmod(anemoi_generator, mulmod(tmp, tmp, r), r),
                            r
                        )

                        term4 := mulmod(term4, term4_tmp, r)

                        res := addmod(res, term4, r)
                    }

                    {
                        let term6 := mulmod(
                            mload(ALPHA_POW_9_LOC),
                            mload(PRK_3_EVAL_ZAETA_LOC),
                            r
                        )

                        let term6_tmp := addmod(
                            addmod(
                                addmod(
                                    tmp_sub_w4_polys_eval_zeta_pow_5,
                                    mload(ANEMOI_GENERATOR_INV_LOC),
                                    r
                                ),
                                sub(r, mload(W_POLY_EVAL_ZAETA_OMEGA_1_LOC)),
                                r
                            ),
                            mulmod(
                                anemoi_generator,
                                mulmod(
                                    mload(W_POLY_EVAL_ZAETA_4_LOC),
                                    mload(W_POLY_EVAL_ZAETA_4_LOC),
                                    r
                                ),
                                r
                            ),
                            r
                        )

                        term6 := mulmod(term6, term6_tmp, r)

                        res := addmod(res, term6, r)
                    }
                }

                mstore(R_EVAL_ZETA_LOC, res)
            }

            // 5. derive the linearization polynomial commitment.
            {
                let w0 := mload(W_POLY_EVAL_ZAETA_0_LOC)
                let w1 := mload(W_POLY_EVAL_ZAETA_1_LOC)
                let w2 := mload(W_POLY_EVAL_ZAETA_2_LOC)
                let w3 := mload(W_POLY_EVAL_ZAETA_3_LOC)
                let wo := mload(W_POLY_EVAL_ZAETA_4_LOC)

                scalar_mul(mload(CM_Q0_X_LOC), mload(CM_Q0_Y_LOC), w0)
                let r_commitment_x := mload(mload(0x40))
                let r_commitment_y := mload(add(mload(0x40), 0x20))

                {
                    scalar_mul(mload(CM_Q1_X_LOC), mload(CM_Q1_Y_LOC), w1)
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))

                    scalar_mul(mload(CM_Q2_X_LOC), mload(CM_Q2_Y_LOC), w2)
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))

                    scalar_mul(mload(CM_Q3_X_LOC), mload(CM_Q3_Y_LOC), w3)
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))

                    let w0w1 := mulmod(w0, w1, r)
                    scalar_mul(mload(CM_Q4_X_LOC), mload(CM_Q4_Y_LOC), w0w1)
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))

                    let w2w3 := mulmod(w2, w3, r)
                    scalar_mul(mload(CM_Q5_X_LOC), mload(CM_Q5_Y_LOC), w2w3)
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))

                    point_add(
                        r_commitment_x,
                        r_commitment_y,
                        mload(CM_Q6_X_LOC),
                        mload(CM_Q6_Y_LOC)
                    )
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))

                    scalar_mul(
                        mload(CM_Q7_X_LOC),
                        mload(CM_Q7_Y_LOC),
                        mulmod(mulmod(w0w1, w2w3, r), wo, r)
                    )
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))

                    scalar_mul(
                        mload(CM_Q8_X_LOC),
                        mload(CM_Q8_Y_LOC),
                        sub(r, wo)
                    )
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    let gamma := mload(GAMMA_LOC)
                    let beta_zeta := mulmod(mload(BETA_LOC), mload(ZETA_LOC), r)

                    let tmp := addmod(
                        w0,
                        addmod(gamma, mulmod(mload(K_0_LOC), beta_zeta, r), r),
                        r
                    )
                    let z_scalar := mulmod(tmp, mload(ALPHA_LOC), r)

                    tmp := addmod(
                        w1,
                        addmod(gamma, mulmod(mload(K_1_LOC), beta_zeta, r), r),
                        r
                    )
                    z_scalar := mulmod(tmp, z_scalar, r)

                    tmp := addmod(
                        w2,
                        addmod(gamma, mulmod(mload(K_2_LOC), beta_zeta, r), r),
                        r
                    )
                    z_scalar := mulmod(tmp, z_scalar, r)

                    tmp := addmod(
                        w3,
                        addmod(gamma, mulmod(mload(K_3_LOC), beta_zeta, r), r),
                        r
                    )
                    z_scalar := mulmod(tmp, z_scalar, r)

                    tmp := addmod(
                        wo,
                        addmod(gamma, mulmod(mload(K_4_LOC), beta_zeta, r), r),
                        r
                    )
                    z_scalar := mulmod(tmp, z_scalar, r)

                    z_scalar := addmod(
                        mulmod(
                            mload(FIRST_LAGRANGE_EVAL_ZETA_LOC),
                            mload(ALPHA_POW_2_LOC),
                            r
                        ),
                        z_scalar,
                        r
                    )

                    scalar_mul(mload(CM_Z_X_LOC), mload(CM_Z_Y_LOC), z_scalar)
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    let beta := mload(BETA_LOC)
                    let gamma := mload(GAMMA_LOC)

                    let s_last_poly_scalar := mulmod(
                        mload(ALPHA_LOC),
                        mulmod(mload(Z_EVAL_ZETA_OMEGA_LOC), beta, r),
                        r
                    )

                    let tmp := addmod(
                        w0,
                        addmod(
                            gamma,
                            mulmod(beta, mload(S_POLY_EVAL_ZAETA_0_LOC), r),
                            r
                        ),
                        r
                    )
                    s_last_poly_scalar := mulmod(s_last_poly_scalar, tmp, r)

                    tmp := addmod(
                        w1,
                        addmod(
                            gamma,
                            mulmod(beta, mload(S_POLY_EVAL_ZAETA_1_LOC), r),
                            r
                        ),
                        r
                    )
                    s_last_poly_scalar := mulmod(s_last_poly_scalar, tmp, r)

                    tmp := addmod(
                        w2,
                        addmod(
                            gamma,
                            mulmod(beta, mload(S_POLY_EVAL_ZAETA_2_LOC), r),
                            r
                        ),
                        r
                    )
                    s_last_poly_scalar := mulmod(s_last_poly_scalar, tmp, r)

                    tmp := addmod(
                        w3,
                        addmod(
                            gamma,
                            mulmod(beta, mload(S_POLY_EVAL_ZAETA_3_LOC), r),
                            r
                        ),
                        r
                    )
                    s_last_poly_scalar := mulmod(s_last_poly_scalar, tmp, r)

                    scalar_mul(
                        mload(CM_S4_X_LOC),
                        mload(CM_S4_Y_LOC),
                        sub(r, s_last_poly_scalar)
                    )
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    let w1_part := mulmod(
                        w1,
                        mulmod(
                            mload(ALPHA_POW_3_LOC),
                            addmod(w1, sub(r, 1), r),
                            r
                        ),
                        r
                    )
                    let w2_part := mulmod(
                        w2,
                        mulmod(
                            mload(ALPHA_POW_4_LOC),
                            addmod(w2, sub(r, 1), r),
                            r
                        ),
                        r
                    )
                    let w3_part := mulmod(
                        w3,
                        mulmod(
                            mload(ALPHA_POW_5_LOC),
                            addmod(w3, sub(r, 1), r),
                            r
                        ),
                        r
                    )
                    let w_part := addmod(
                        w1_part,
                        addmod(w2_part, w3_part, r),
                        r
                    )

                    scalar_mul(mload(CM_QB_X_LOC), mload(CM_QB_Y_LOC), w_part)
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    let q_prk3_0 := mulmod(
                        mload(PRK_3_EVAL_ZAETA_LOC),
                        mload(ALPHA_POW_6_LOC),
                        r
                    )
                    let q_prk3_1 := mulmod(
                        mload(PRK_3_EVAL_ZAETA_LOC),
                        mload(ALPHA_POW_7_LOC),
                        r
                    )

                    scalar_mul(
                        mload(CM_PRK_0_X_LOC),
                        mload(CM_PRK_0_Y_LOC),
                        q_prk3_0
                    )
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))

                    scalar_mul(
                        mload(CM_PRK_1_X_LOC),
                        mload(CM_PRK_1_Y_LOC),
                        q_prk3_1
                    )
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    let factor := pow_small(
                        mload(ZETA_LOC),
                        add(mload(CS_SIZE_LOC), 2)
                    )
                    let exponent_0 := mulmod(
                        mload(Z_H_EVAL_ZETA_LOC),
                        factor,
                        r
                    )
                    let exponent_1 := mulmod(exponent_0, factor, r)
                    let exponent_2 := mulmod(exponent_1, factor, r)
                    let exponent_3 := mulmod(exponent_2, factor, r)

                    scalar_mul(
                        mload(CM_T0_X_LOC),
                        mload(CM_T0_Y_LOC),
                        sub(r, mload(Z_H_EVAL_ZETA_LOC))
                    )
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))

                    scalar_mul(
                        mload(CM_T1_X_LOC),
                        mload(CM_T1_Y_LOC),
                        sub(r, exponent_0)
                    )
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))

                    scalar_mul(
                        mload(CM_T2_X_LOC),
                        mload(CM_T2_Y_LOC),
                        sub(r, exponent_1)
                    )
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))

                    scalar_mul(
                        mload(CM_T3_X_LOC),
                        mload(CM_T3_Y_LOC),
                        sub(r, exponent_2)
                    )
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))

                    scalar_mul(
                        mload(CM_T4_X_LOC),
                        mload(CM_T4_Y_LOC),
                        sub(r, exponent_3)
                    )
                    point_add_in_memory(r_commitment_x, r_commitment_y)
                    r_commitment_x := mload(mload(0x40))
                    r_commitment_y := mload(add(mload(0x40), 0x20))
                }

                mstore(R_COMMITMENT_X_LOC, r_commitment_x)
                mstore(R_COMMITMENT_Y_LOC, r_commitment_y)
            }

            // 6. Combine multiple commitments(opening in zeta) into one commitment.
            {
                let commitment_x := mload(CM_W0_X_LOC)
                let commitment_y := mload(CM_W0_Y_LOC)

                let multiplier := 1
                let eval_combined := mload(W_POLY_EVAL_ZAETA_0_LOC)
                let alpha := mload(ALPHA_BATCH_12_LOC)

                {
                    multiplier := mulmod(multiplier, alpha, r)
                    eval_combined := addmod(
                        eval_combined,
                        mulmod(mload(W_POLY_EVAL_ZAETA_1_LOC), multiplier, r),
                        r
                    )

                    scalar_mul(
                        mload(CM_W1_X_LOC),
                        mload(CM_W1_Y_LOC),
                        multiplier
                    )
                    point_add_in_memory(commitment_x, commitment_y)
                    commitment_x := mload(mload(0x40))
                    commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    multiplier := mulmod(multiplier, alpha, r)
                    eval_combined := addmod(
                        eval_combined,
                        mulmod(mload(W_POLY_EVAL_ZAETA_2_LOC), multiplier, r),
                        r
                    )

                    scalar_mul(
                        mload(CM_W2_X_LOC),
                        mload(CM_W2_Y_LOC),
                        multiplier
                    )
                    point_add_in_memory(commitment_x, commitment_y)
                    commitment_x := mload(mload(0x40))
                    commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    multiplier := mulmod(multiplier, alpha, r)
                    eval_combined := addmod(
                        eval_combined,
                        mulmod(mload(W_POLY_EVAL_ZAETA_3_LOC), multiplier, r),
                        r
                    )

                    scalar_mul(
                        mload(CM_W3_X_LOC),
                        mload(CM_W3_Y_LOC),
                        multiplier
                    )
                    point_add_in_memory(commitment_x, commitment_y)
                    commitment_x := mload(mload(0x40))
                    commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    multiplier := mulmod(multiplier, alpha, r)
                    eval_combined := addmod(
                        eval_combined,
                        mulmod(mload(W_POLY_EVAL_ZAETA_4_LOC), multiplier, r),
                        r
                    )

                    scalar_mul(
                        mload(CM_W4_X_LOC),
                        mload(CM_W4_Y_LOC),
                        multiplier
                    )
                    point_add_in_memory(commitment_x, commitment_y)
                    commitment_x := mload(mload(0x40))
                    commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    multiplier := mulmod(multiplier, alpha, r)
                    eval_combined := addmod(
                        eval_combined,
                        mulmod(mload(S_POLY_EVAL_ZAETA_0_LOC), multiplier, r),
                        r
                    )

                    scalar_mul(
                        mload(CM_S0_X_LOC),
                        mload(CM_S0_Y_LOC),
                        multiplier
                    )
                    point_add_in_memory(commitment_x, commitment_y)
                    commitment_x := mload(mload(0x40))
                    commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    let multiplier_6 := mulmod(multiplier, alpha, r)
                    eval_combined := addmod(
                        eval_combined,
                        mulmod(mload(S_POLY_EVAL_ZAETA_1_LOC), multiplier_6, r),
                        r
                    )
                    multiplier := multiplier_6

                    scalar_mul(
                        mload(CM_S1_X_LOC),
                        mload(CM_S1_Y_LOC),
                        multiplier
                    )
                    point_add_in_memory(commitment_x, commitment_y)
                    commitment_x := mload(mload(0x40))
                    commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    multiplier := mulmod(multiplier, alpha, r)
                    eval_combined := addmod(
                        eval_combined,
                        mulmod(mload(S_POLY_EVAL_ZAETA_2_LOC), multiplier, r),
                        r
                    )

                    scalar_mul(
                        mload(CM_S2_X_LOC),
                        mload(CM_S2_Y_LOC),
                        multiplier
                    )
                    point_add_in_memory(commitment_x, commitment_y)
                    commitment_x := mload(mload(0x40))
                    commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    multiplier := mulmod(multiplier, alpha, r)
                    eval_combined := addmod(
                        eval_combined,
                        mulmod(mload(S_POLY_EVAL_ZAETA_3_LOC), multiplier, r),
                        r
                    )

                    scalar_mul(
                        mload(CM_S3_X_LOC),
                        mload(CM_S3_Y_LOC),
                        multiplier
                    )
                    point_add_in_memory(commitment_x, commitment_y)
                    commitment_x := mload(mload(0x40))
                    commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    multiplier := mulmod(multiplier, alpha, r)
                    eval_combined := addmod(
                        eval_combined,
                        mulmod(mload(PRK_3_EVAL_ZAETA_LOC), multiplier, r),
                        r
                    )

                    scalar_mul(
                        mload(CM_PRK_2_X_LOC),
                        mload(CM_PRK_2_Y_LOC),
                        multiplier
                    )
                    point_add_in_memory(commitment_x, commitment_y)
                    commitment_x := mload(mload(0x40))
                    commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    multiplier := mulmod(multiplier, alpha, r)
                    eval_combined := addmod(
                        eval_combined,
                        mulmod(mload(PRK_4_EVAL_ZAETA_LOC), multiplier, r),
                        r
                    )

                    scalar_mul(
                        mload(CM_PRK_3_X_LOC),
                        mload(CM_PRK_3_Y_LOC),
                        multiplier
                    )
                    point_add_in_memory(commitment_x, commitment_y)
                    commitment_x := mload(mload(0x40))
                    commitment_y := mload(add(mload(0x40), 0x20))
                }

                {
                    multiplier := mulmod(multiplier, alpha, r)
                    eval_combined := addmod(
                        eval_combined,
                        mulmod(mload(R_EVAL_ZETA_LOC), multiplier, r),
                        r
                    )

                    scalar_mul(
                        mload(R_COMMITMENT_X_LOC),
                        mload(R_COMMITMENT_Y_LOC),
                        multiplier
                    )
                    point_add_in_memory(commitment_x, commitment_y)
                    commitment_x := mload(mload(0x40))
                    commitment_y := mload(add(mload(0x40), 0x20))
                }

                mstore(COMMITMENT_X_LOC, commitment_x)
                mstore(COMMITMENT_Y_LOC, commitment_y)
                mstore(VALUE_LOC, eval_combined)
            }

            // 7. Combine multiple commitments(opening in zeta omega) into one commitment.
            {
                let batc_commitment_x := mload(CM_Z_X_LOC)
                let batc_commitment_y := mload(CM_Z_Y_LOC)

                let alpha := mload(ALPHA_BATCH_4_LOC)
                let multiplier := alpha
                let eval_combined := addmod(
                    mload(Z_EVAL_ZETA_OMEGA_LOC),
                    mulmod(mload(W_POLY_EVAL_ZAETA_OMEGA_0_LOC), multiplier, r),
                    r
                )
                scalar_mul(mload(CM_W0_X_LOC), mload(CM_W0_Y_LOC), multiplier)
                point_add_in_memory(batc_commitment_x, batc_commitment_y)
                batc_commitment_x := mload(mload(0x40))
                batc_commitment_y := mload(add(mload(0x40), 0x20))

                multiplier := mulmod(multiplier, alpha, r)
                eval_combined := addmod(
                    eval_combined,
                    mulmod(mload(W_POLY_EVAL_ZAETA_OMEGA_1_LOC), multiplier, r),
                    r
                )
                scalar_mul(mload(CM_W1_X_LOC), mload(CM_W1_Y_LOC), multiplier)
                point_add_in_memory(batc_commitment_x, batc_commitment_y)
                batc_commitment_x := mload(mload(0x40))
                batc_commitment_y := mload(add(mload(0x40), 0x20))

                multiplier := mulmod(multiplier, alpha, r)
                eval_combined := addmod(
                    eval_combined,
                    mulmod(mload(W_POLY_EVAL_ZAETA_OMEGA_2_LOC), multiplier, r),
                    r
                )
                scalar_mul(mload(CM_W2_X_LOC), mload(CM_W2_Y_LOC), multiplier)
                point_add_in_memory(batc_commitment_x, batc_commitment_y)
                batc_commitment_x := mload(mload(0x40))
                batc_commitment_y := mload(add(mload(0x40), 0x20))

                mstore(BATCH_COMMITMENT_X_LOC, batc_commitment_x)
                mstore(BATCH_COMMITMENT_Y_LOC, batc_commitment_y)
                mstore(BATCH_VALUE_LOC, eval_combined)
            }

            // 8. atch verify proofs with different points.
            {
                scalar_mul(
                    mload(OPENING_ZETA_X_LOC),
                    mload(OPENING_ZETA_Y_LOC),
                    mload(ZETA_LOC)
                )
                let p0_zeta_x := mload(mload(0x40))
                let p0_zeta_y := mload(add(mload(0x40), 0x20))

                scalar_mul(
                    mload(OPENING_ZETA_OMEGA_X_LOC),
                    mload(OPENING_ZETA_OMEGA_Y_LOC),
                    mload(U_LOC)
                )
                let p1_u_x := mload(mload(0x40))
                let p1_u_y := mload(add(mload(0x40), 0x20))

                scalar_mul(
                    p1_u_x,
                    p1_u_y,
                    mulmod(mload(ROOT_LOC), mload(ZETA_LOC), r)
                )
                let p1_u_zata_omega_x := mload(mload(0x40))
                let p1_u_zata_omega_y := mload(add(mload(0x40), 0x20))

                point_add(
                    mload(OPENING_ZETA_X_LOC),
                    mload(OPENING_ZETA_Y_LOC),
                    p1_u_x,
                    p1_u_y
                )
                let left_first_x := mload(mload(0x40))
                let left_first_y := mload(add(mload(0x40), 0x20))

                point_add(
                    p0_zeta_x,
                    p0_zeta_y,
                    p1_u_zata_omega_x,
                    p1_u_zata_omega_y
                )
                let right_first_x := mload(mload(0x40))
                let right_first_y := mload(add(mload(0x40), 0x20))

                scalar_mul(
                    mload(BATCH_COMMITMENT_X_LOC),
                    mload(BATCH_COMMITMENT_Y_LOC),
                    mload(U_LOC)
                )
                point_add_in_memory(
                    mload(COMMITMENT_X_LOC),
                    mload(COMMITMENT_Y_LOC)
                )
                let right_first_comm_x := mload(mload(0x40))
                let right_first_comm_y := mload(add(mload(0x40), 0x20))

                scalar_mul(
                    1,
                    2,
                    sub(
                        r,
                        addmod(
                            mload(VALUE_LOC),
                            mulmod(mload(BATCH_VALUE_LOC), mload(U_LOC), r),
                            r
                        )
                    )
                )
                point_add_in_memory(right_first_x, right_first_y)
                right_first_x := mload(mload(0x40))
                right_first_y := mload(add(mload(0x40), 0x20))

                point_add(
                    right_first_x,
                    right_first_y,
                    right_first_comm_x,
                    right_first_comm_y
                )
                right_first_x := mload(mload(0x40))
                right_first_y := mload(add(mload(0x40), 0x20))

                mstore(mload(0x40), left_first_x)
                mstore(add(mload(0x40), 0x20), left_first_y)
                mstore(
                    add(mload(0x40), 0x40),
                    0x260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1
                )
                mstore(
                    add(mload(0x40), 0x60),
                    0x0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0
                )
                mstore(
                    add(mload(0x40), 0x80),
                    0x04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4
                )
                mstore(
                    add(mload(0x40), 0xa0),
                    0x22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55
                )

                mstore(add(mload(0x40), 0xc0), right_first_x)
                mstore(
                    add(mload(0x40), 0xe0),
                    sub(
                        21888242871839275222246405745257275088696311157297823662689037894645226208583,
                        right_first_y
                    )
                )
                mstore(
                    add(mload(0x40), 0x100),
                    0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
                )
                mstore(
                    add(mload(0x40), 0x120),
                    0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
                )
                mstore(
                    add(mload(0x40), 0x140),
                    0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
                )
                mstore(
                    add(mload(0x40), 0x160),
                    0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
                )

                let success_flag := staticcall(
                    gas(),
                    8,
                    mload(0x40),
                    0x180,
                    mload(0x40),
                    0x20
                )

                let is_success := and(mload(mload(SUCCESS_LOC)), success_flag)
                if iszero(is_success) {
                    revert(0x00, 0x00)
                }

                return(mload(0x40), 0x20)
            }
        }
    }
}
