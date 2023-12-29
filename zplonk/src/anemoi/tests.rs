use crate::anemoi::bn254::AnemoiJive254;
use crate::anemoi::mds::{ApplicableMDSMatrix, MDSMatrix};
use crate::anemoi::{AnemoiJive, N_ANEMOI_ROUNDS};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, MontFp};

#[test]
fn test_anemoi_variable_length_hash() {
    type F = Fr;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];

    let res = AnemoiJive254::eval_variable_length_hash(&input);
    assert_eq!(
        res,
        MontFp!("16130067210949763713397506837063979419501098552211549704252212995440438798911")
    );
}

#[test]
fn test_anemoi_variable_length_hash_flatten() {
    type F = Fr;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];

    let trace = AnemoiJive254::eval_variable_length_hash_with_trace(&input);

    assert_eq!(trace.input, input.to_vec());

    let mut input = input.to_vec();

    let mds = MDSMatrix::<F, 2>(AnemoiJive254::MDS_MATRIX);

    if input.len() % (2 * 2 - 1) != 0 || input.is_empty() {
        input.push(F::ONE);
        if input.len() % (2 * 2 - 1) != 0 {
            input.extend_from_slice(&[F::ZERO].repeat(2 * 2 - 1 - (input.len() % (2 * 2 - 1))));
        }
    }

    // after the previous step, the length of input must be multiplies of `2 * N - 1`.
    assert_eq!(input.len() % (2 * 2 - 1), 0);

    let mut x = [F::ZERO; 2];
    let mut y = [F::ZERO; 2];
    for (rr, chuck) in input.chunks_exact(2 * 2 - 1).enumerate() {
        for i in 0..2 {
            x[i] += &chuck[i];
        }
        for i in 0..(2 - 1) {
            y[i] += &chuck[2 + i];
        }

        assert_eq!(x, trace.before_permutation[rr].0);
        assert_eq!(y, trace.before_permutation[rr].1);

        // first round
        {
            let a_i_minus_1 = trace.before_permutation[rr].0[0].clone();
            let b_i_minus_1 = trace.before_permutation[rr].0[1].clone();
            let c_i_minus_1 = trace.before_permutation[rr].1[0].clone();
            let d_i_minus_1 = trace.before_permutation[rr].1[1].clone();

            let a_i = trace.intermediate_values_before_constant_additions[rr].0[0][0].clone();
            let b_i = trace.intermediate_values_before_constant_additions[rr].0[0][1].clone();
            let c_i = trace.intermediate_values_before_constant_additions[rr].1[0][0].clone();
            let d_i = trace.intermediate_values_before_constant_additions[rr].1[0][1].clone();

            let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
            let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
            let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
            let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

            let g = AnemoiJive254::GENERATOR;
            let g2 = AnemoiJive254::GENERATOR_SQUARE_PLUS_ONE;

            // equation 1
            let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                - &c_i)
                .pow(&[5u64])
                + g * (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c)
                    .square();
            let right = (a_i_minus_1.double() + d_i_minus_1)
                + g * (b_i_minus_1.double() + c_i_minus_1)
                + prk_i_a;
            assert_eq!(left, right);

            // equation 2
            let left =
                (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                    - &d_i)
                    .pow(&[5u64])
                    + g * (g * (a_i_minus_1 + d_i_minus_1)
                        + g2 * (b_i_minus_1 + c_i_minus_1)
                        + prk_i_d)
                        .square();
            let right = g * (a_i_minus_1.double() + d_i_minus_1)
                + g2 * (b_i_minus_1.double() + c_i_minus_1)
                + prk_i_b;
            assert_eq!(left, right);

            // equation 3
            let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                - &c_i)
                .pow(&[5u64])
                + g * c_i.square()
                + AnemoiJive254::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left =
                (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                    - &d_i)
                    .pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive254::GENERATOR_INV;
            let right = b_i;
            assert_eq!(left, right);
        }

        // remaining rounds
        for r in 1..N_ANEMOI_ROUNDS {
            let a_i_minus_1 =
                trace.intermediate_values_before_constant_additions[rr].0[r - 1][0].clone();
            let b_i_minus_1 =
                trace.intermediate_values_before_constant_additions[rr].0[r - 1][1].clone();
            let c_i_minus_1 =
                trace.intermediate_values_before_constant_additions[rr].1[r - 1][0].clone();
            let d_i_minus_1 =
                trace.intermediate_values_before_constant_additions[rr].1[r - 1][1].clone();

            let a_i = trace.intermediate_values_before_constant_additions[rr].0[r][0].clone();
            let b_i = trace.intermediate_values_before_constant_additions[rr].0[r][1].clone();
            let c_i = trace.intermediate_values_before_constant_additions[rr].1[r][0].clone();
            let d_i = trace.intermediate_values_before_constant_additions[rr].1[r][1].clone();

            let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
            let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
            let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
            let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

            let g = AnemoiJive254::GENERATOR;
            let g2 = AnemoiJive254::GENERATOR_SQUARE_PLUS_ONE;

            // equation 1
            let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                - &c_i)
                .pow(&[5u64])
                + g * (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c)
                    .square();
            let right = (a_i_minus_1.double() + d_i_minus_1)
                + g * (b_i_minus_1.double() + c_i_minus_1)
                + prk_i_a;
            assert_eq!(left, right);

            // equation 2
            let left =
                (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                    - &d_i)
                    .pow(&[5u64])
                    + g * (g * (a_i_minus_1 + d_i_minus_1)
                        + g2 * (b_i_minus_1 + c_i_minus_1)
                        + prk_i_d)
                        .square();
            let right = g * (a_i_minus_1.double() + d_i_minus_1)
                + g2 * (b_i_minus_1.double() + c_i_minus_1)
                + prk_i_b;
            assert_eq!(left, right);

            // equation 3
            let left = (a_i_minus_1 + d_i_minus_1 + g * (b_i_minus_1 + c_i_minus_1) + prk_i_c
                - &c_i)
                .pow(&[5u64])
                + g * c_i.square()
                + AnemoiJive254::GENERATOR_INV;
            let right = a_i;
            assert_eq!(left, right);

            // equation 4
            let left =
                (g * (a_i_minus_1 + d_i_minus_1) + g2 * (b_i_minus_1 + c_i_minus_1) + prk_i_d
                    - &d_i)
                    .pow(&[5u64])
                    + g * d_i.square()
                    + AnemoiJive254::GENERATOR_INV;
            let right = b_i;
            assert_eq!(left, right);
        }

        x = trace.intermediate_values_before_constant_additions[rr].0[N_ANEMOI_ROUNDS - 1].clone();
        y = trace.intermediate_values_before_constant_additions[rr].1[N_ANEMOI_ROUNDS - 1].clone();
        mds.permute_in_place(&mut x, &mut y);

        for i in 0..2 {
            y[i] += &x[i];
            x[i] += &y[i];
        }

        assert_eq!(x, trace.after_permutation[rr].0);
        assert_eq!(y, trace.after_permutation[rr].1);
    }

    assert_eq!(trace.output, x[0]);
}
