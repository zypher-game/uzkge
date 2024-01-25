use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, MontFp, One, Zero};

use crate::anemoi::{
    bn254::AnemoiJive254,
    mds::{ApplicableMDSMatrix, MDSMatrix},
    AnemoiJive, N_ANEMOI_ROUNDS,
};

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

#[test]
fn test_eval_stream_cipher() {
    type F = Fr;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];

    let expect = vec![
        MontFp!("16130067210949763713397506837063979419501098552211549704252212995440438798911"),
        MontFp!("18590584568098617896724185569639323829868938535309403007069063053202089323797"),
        MontFp!("7427714548193519784948478077278071182205330098717288886731852935822331538384"),
        MontFp!("13626963569912088497291344349536792174753053314620332421784946842426303540601"),
        MontFp!("5934436484331665251730570275822474366622075032279676505146445889842358848865"),
        MontFp!("15737389356547749545883600010888859196953327088251528704115120849521328172216"),
        MontFp!("2098518999685021281661943698742854255835815276942992547535880627233402615577"),
    ];

    let res = AnemoiJive254::eval_stream_cipher(&input, 2);
    assert_eq!(res, expect[..2]);

    let res = AnemoiJive254::eval_stream_cipher(&input, 4);
    assert_eq!(res, expect[..4]);

    let res = AnemoiJive254::eval_stream_cipher(&input, 6);
    assert_eq!(res, expect[..6]);

    let res = AnemoiJive254::eval_stream_cipher(&input, 7);
    assert_eq!(res, expect[..7]);
}

#[test]
fn test_eval_stream_cipher_flatten() {
    type F = Fr;

    let input = [F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];
    let output_len = 7;
    let mut output = Vec::with_capacity(output_len);

    let trace = AnemoiJive254::eval_stream_cipher_with_trace(&input, output_len);

    assert_eq!(trace.input, input.to_vec());

    let mut input = input.to_vec();

    let mds = MDSMatrix::<F, 2>(AnemoiJive254::MDS_MATRIX);

    if input.len() % (2 * 2 - 1) != 0 || input.is_empty() {
        input.push(F::one());
        if input.len() % (2 * 2 - 1) != 0 {
            input.extend_from_slice(&[F::zero()].repeat(2 * 2 - 1 - (input.len() % (2 * 2 - 1))));
        }
    }

    // after the previous step, the length of input must be multiplies of `2 * N - 1`.
    assert_eq!(input.len() % (2 * 2 - 1), 0);

    let g = AnemoiJive254::GENERATOR;
    let g2 = AnemoiJive254::GENERATOR_SQUARE_PLUS_ONE;

    let mut x = [F::zero(); 2];
    let mut y = [F::zero(); 2];
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
        for r in 1..14 {
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

        x = trace.intermediate_values_before_constant_additions[rr].0[14 - 1].clone();
        y = trace.intermediate_values_before_constant_additions[rr].1[14 - 1].clone();
        mds.permute_in_place(&mut x, &mut y);
        for i in 0..2 {
            y[i] += &x[i];
            x[i] += &y[i];
        }

        assert_eq!(x, trace.after_permutation[rr].0);
        assert_eq!(y, trace.after_permutation[rr].1);
    }

    if output_len <= 2 {
        output.extend_from_slice(&x[..output_len])
    } else if output_len > 2 && output_len <= (2 * 2 - 1) {
        output.extend_from_slice(&x);
        output.extend_from_slice(&y[..output_len - 2])
    } else if output_len > (2 * 2 - 1) {
        output.extend_from_slice(&x);
        output.extend_from_slice(&y[..2 - 1]);

        let absorbing_times = input.len() / (2 * 2 - 1);
        let squeezing_times = output_len / (2 * 2 - 1) - 1;
        let remaining = output_len % (2 * 2 - 1);

        for i in 0..squeezing_times {
            // first round
            {
                let a_i_minus_1 = trace.before_permutation[absorbing_times + i].0[0].clone();
                let b_i_minus_1 = trace.before_permutation[absorbing_times + i].0[1].clone();
                let c_i_minus_1 = trace.before_permutation[absorbing_times + i].1[0].clone();
                let d_i_minus_1 = trace.before_permutation[absorbing_times + i].1[1].clone();

                let a_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .0[0][0]
                    .clone();
                let b_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .0[0][1]
                    .clone();
                let c_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .1[0][0]
                    .clone();
                let d_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .1[0][1]
                    .clone();

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
            for r in 1..14 {
                let a_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + i]
                    .0[r - 1][0]
                    .clone();
                let b_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + i]
                    .0[r - 1][1]
                    .clone();
                let c_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + i]
                    .1[r - 1][0]
                    .clone();
                let d_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + i]
                    .1[r - 1][1]
                    .clone();

                let a_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .0[r][0]
                    .clone();
                let b_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .0[r][1]
                    .clone();
                let c_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .1[r][0]
                    .clone();
                let d_i = trace.intermediate_values_before_constant_additions[absorbing_times + i]
                    .1[r][1]
                    .clone();

                let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
                let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
                let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
                let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

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

            x = trace.intermediate_values_before_constant_additions[absorbing_times + i].0[14 - 1]
                .clone();
            y = trace.intermediate_values_before_constant_additions[absorbing_times + i].1[14 - 1]
                .clone();
            mds.permute_in_place(&mut x, &mut y);
            for i in 0..2 {
                y[i] += &x[i];
                x[i] += &y[i];
            }

            assert_eq!(x, trace.after_permutation[absorbing_times + i].0);
            assert_eq!(y, trace.after_permutation[absorbing_times + i].1);

            output.extend_from_slice(&x);
            output.extend_from_slice(&y[..2 - 1]);
        }

        if remaining > 0 {
            // first round
            {
                let a_i_minus_1 =
                    trace.before_permutation[absorbing_times + squeezing_times].0[0].clone();
                let b_i_minus_1 =
                    trace.before_permutation[absorbing_times + squeezing_times].0[1].clone();
                let c_i_minus_1 =
                    trace.before_permutation[absorbing_times + squeezing_times].1[0].clone();
                let d_i_minus_1 =
                    trace.before_permutation[absorbing_times + squeezing_times].1[1].clone();

                let a_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .0[0][0]
                    .clone();
                let b_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .0[0][1]
                    .clone();
                let c_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .1[0][0]
                    .clone();
                let d_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .1[0][1]
                    .clone();

                let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][0].clone();
                let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[0][1].clone();
                let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][0].clone();
                let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[0][1].clone();

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
            for r in 1..14 {
                let a_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .0[r - 1][0]
                    .clone();
                let b_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .0[r - 1][1]
                    .clone();
                let c_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .1[r - 1][0]
                    .clone();
                let d_i_minus_1 = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .1[r - 1][1]
                    .clone();

                let a_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .0[r][0]
                    .clone();
                let b_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .0[r][1]
                    .clone();
                let c_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .1[r][0]
                    .clone();
                let d_i = trace.intermediate_values_before_constant_additions
                    [absorbing_times + squeezing_times]
                    .1[r][1]
                    .clone();

                let prk_i_a = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][0].clone();
                let prk_i_b = AnemoiJive254::PREPROCESSED_ROUND_KEYS_X[r][1].clone();
                let prk_i_c = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][0].clone();
                let prk_i_d = AnemoiJive254::PREPROCESSED_ROUND_KEYS_Y[r][1].clone();

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

            x = trace.intermediate_values_before_constant_additions
                [absorbing_times + squeezing_times]
                .0[14 - 1]
                .clone();
            y = trace.intermediate_values_before_constant_additions
                [absorbing_times + squeezing_times]
                .1[14 - 1]
                .clone();
            mds.permute_in_place(&mut x, &mut y);
            for i in 0..2 {
                y[i] += &x[i];
                x[i] += &y[i];
            }

            assert_eq!(
                x,
                trace.after_permutation[absorbing_times + squeezing_times].0
            );
            assert_eq!(
                y,
                trace.after_permutation[absorbing_times + squeezing_times].1
            );

            let mut x = x.to_vec();
            x.extend_from_slice(&y);
            output.extend_from_slice(&x[..remaining]);
        }
    }

    assert_eq!(trace.output, output);
}
