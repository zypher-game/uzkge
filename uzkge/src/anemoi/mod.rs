/// The module for the AnemoiJive254 data structure.
mod bn254;
/// The module for the MDS matrices.
mod mds;

/// The module for the trace data structure.
mod traces;
pub use traces::*;

/// The module for tests.
#[cfg(test)]
mod tests;

use ark_ff::PrimeField;
pub use bn254::*;

use crate::anemoi::mds::{ApplicableMDSMatrix, MDSMatrix};

/// The trait for the Anemoi-Jive parameters.
pub trait AnemoiJive<F: PrimeField, const N: usize, const NUM_ROUNDS: usize>
where
    MDSMatrix<F, N>: ApplicableMDSMatrix<F, N>,
{
    /// The S-Box alpha value.
    const ALPHA: u32;

    /// The generator of the group.
    const GENERATOR: F;

    /// Delta, which is the inverse of the generator.
    const GENERATOR_INV: F;

    /// Used in the MDS. The square of the generator plus one.
    const GENERATOR_SQUARE_PLUS_ONE: F;

    /// The first group of the round keys.
    const ROUND_KEYS_X: [[F; N]; NUM_ROUNDS];

    /// The second group of the round keys.
    const ROUND_KEYS_Y: [[F; N]; NUM_ROUNDS];

    /// The first group of the round keys that have been preprocessed with the MDS.
    const PREPROCESSED_ROUND_KEYS_X: [[F; N]; NUM_ROUNDS];

    /// The second group of the round keys that have been preprocessed with the MDS.
    const PREPROCESSED_ROUND_KEYS_Y: [[F; N]; NUM_ROUNDS];

    /// The MDS matrix.
    const MDS_MATRIX: [[F; N]; N];

    /// Return the inverse of alpha over `r - 1`.
    fn get_alpha_inv() -> Vec<u64>;

    /// Eval the Anemoi sponge.
    fn eval_variable_length_hash(input: &[F]) -> F {
        let mut input = input.to_vec();

        let sigma = if input.len() % (2 * N - 1) == 0 && !input.is_empty() {
            F::ONE
        } else {
            input.push(F::ONE);
            if input.len() % (2 * N - 1) != 0 {
                input.extend_from_slice(&[F::ZERO].repeat(2 * N - 1 - (input.len() % (2 * N - 1))));
            }

            F::ZERO
        };

        // after the previous step, the length of input must be multiplies of `2 * N - 1`.
        assert_eq!(input.len() % (2 * N - 1), 0);

        // initialize the internal state.
        let mut x = [F::ZERO; N];
        let mut y = [F::ZERO; N];
        for chunk in input.chunks_exact(2 * N - 1) {
            for i in 0..N {
                x[i] += &chunk[i];
            }
            for i in 0..(N - 1) {
                y[i] += &chunk[N + i];
            }

            Self::anemoi_permutation(&mut x, &mut y)
        }
        y[N - 1] += &sigma;
        // This step can be omitted since we only get one element.
        // For formality we keep it here.

        x[0]
    }

    /// Eval the Anemoi sponge and return the trace.
    fn eval_variable_length_hash_with_trace(input: &[F]) -> AnemoiVLHTrace<F, N, NUM_ROUNDS> {
        let mut trace = AnemoiVLHTrace::<F, N, NUM_ROUNDS>::default();

        let mut input = input.to_vec();
        trace.input = input.clone();

        let mds = MDSMatrix::<F, N>(Self::MDS_MATRIX);
        let alpha_inv = Self::get_alpha_inv();

        let sigma = if input.len() % (2 * N - 1) == 0 && !input.is_empty() {
            F::ONE
        } else {
            input.push(F::ONE);
            if input.len() % (2 * N - 1) != 0 {
                input.extend_from_slice(&[F::ZERO].repeat(2 * N - 1 - (input.len() % (2 * N - 1))));
            }

            F::ZERO
        };

        // after the previous step, the length of input must be multiplies of `2 * N - 1`.
        assert_eq!(input.len() % (2 * N - 1), 0);

        // initialize the internal state.
        let mut x = [F::ZERO; N];
        let mut y = [F::ZERO; N];
        for chunk in input.chunks_exact(2 * N - 1) {
            for i in 0..N {
                x[i] += &chunk[i];
            }
            for i in 0..(N - 1) {
                y[i] += &chunk[N + i];
            }

            trace.before_permutation.push((x.clone(), y.clone()));

            let mut intermediate_values_before_constant_additions =
                ([[F::ZERO; N]; NUM_ROUNDS], [[F::ZERO; N]; NUM_ROUNDS]);
            for r in 0..NUM_ROUNDS {
                for i in 0..N {
                    x[i] += &Self::ROUND_KEYS_X[r][i];
                    y[i] += &Self::ROUND_KEYS_Y[r][i];
                }
                mds.permute_in_place(&mut x, &mut y);
                for i in 0..N {
                    y[i] += &x[i];
                    x[i] += &y[i];
                }
                for i in 0..N {
                    x[i] -= &(Self::GENERATOR * &(y[i].square()));
                    y[i] -= &x[i].pow(&alpha_inv);
                    x[i] += &(Self::GENERATOR * &(y[i].square()) + Self::GENERATOR_INV);
                }

                intermediate_values_before_constant_additions.0[r] = x.clone();
                intermediate_values_before_constant_additions.1[r] = y.clone();
            }

            mds.permute_in_place(&mut x, &mut y);
            for i in 0..N {
                y[i] += &x[i];
                x[i] += &y[i];
            }

            trace
                .intermediate_values_before_constant_additions
                .push(intermediate_values_before_constant_additions);

            trace.after_permutation.push((x.clone(), y.clone()));
        }
        y[N - 1] += &sigma;
        // This step can be omitted since we only get one element.
        // For formality we keep it here.

        trace.output = x[0];

        trace
    }

    /// Eval the the Anemoi-Jive stream cipher.
    fn eval_stream_cipher(input: &[F], output_len: usize) -> Vec<F> {
        let mut input = input.to_vec();
        let mut output = Vec::with_capacity(output_len);

        let sigma = if input.len() % (2 * N - 1) == 0 && !input.is_empty() {
            F::one()
        } else {
            input.push(F::one());
            if input.len() % (2 * N - 1) != 0 {
                input.extend_from_slice(
                    &[F::zero()].repeat(2 * N - 1 - (input.len() % (2 * N - 1))),
                );
            }

            F::zero()
        };

        // after the previous step, the length of input must be multiplies of `2 * N - 1`.
        assert_eq!(input.len() % (2 * N - 1), 0);

        // initialize the internal state.
        let mut x = [F::zero(); N];
        let mut y = [F::zero(); N];
        for chunk in input.chunks_exact(2 * N - 1) {
            for i in 0..N {
                x[i] += &chunk[i];
            }
            for i in 0..(N - 1) {
                y[i] += &chunk[N + i];
            }

            Self::anemoi_permutation(&mut x, &mut y)
        }
        y[N - 1] += &sigma;

        if output_len <= N {
            output.extend_from_slice(&x[..output_len])
        } else if output_len > N && output_len <= (2 * N - 1) {
            output.extend_from_slice(&x);
            output.extend_from_slice(&y[..output_len - N])
        } else if output_len > (2 * N - 1) {
            output.extend_from_slice(&x);
            output.extend_from_slice(&y[..N - 1]);

            let squeezing_times = output_len / (2 * N - 1) - 1;
            let remaining = output_len % (2 * N - 1);

            for _ in 0..squeezing_times {
                Self::anemoi_permutation(&mut x, &mut y);
                output.extend_from_slice(&x);
                output.extend_from_slice(&y[..N - 1]);
            }

            if remaining > 0 {
                Self::anemoi_permutation(&mut x, &mut y);
                let mut x = x.to_vec();
                x.extend_from_slice(&y);
                output.extend_from_slice(&x[..remaining]);
            }
        }

        output
    }

    /// Eval the the Anemoi-Jive stream cipher and return the trace.
    fn eval_stream_cipher_with_trace(
        input: &[F],
        output_len: usize,
    ) -> AnemoiStreamCipherTrace<F, N, NUM_ROUNDS> {
        let mut trace = AnemoiStreamCipherTrace::<F, N, NUM_ROUNDS>::default();

        let mut input = input.to_vec();
        trace.input = input.clone();

        let mds = MDSMatrix::<F, N>(Self::MDS_MATRIX);
        let alpha_inv = Self::get_alpha_inv();

        let sigma = if input.len() % (2 * N - 1) == 0 && !input.is_empty() {
            F::one()
        } else {
            input.push(F::one());
            if input.len() % (2 * N - 1) != 0 {
                input.extend_from_slice(
                    &[F::zero()].repeat(2 * N - 1 - (input.len() % (2 * N - 1))),
                );
            }

            F::zero()
        };

        // after the previous step, the length of input must be multiplies of `2 * N - 1`.
        assert_eq!(input.len() % (2 * N - 1), 0);

        // applies an Anemoi permutation with trace to the state
        let mut anemoi_permutation_with_trace = |x: &mut [F; N], y: &mut [F; N]| {
            trace.before_permutation.push((*x, *y));

            let mut intermediate_values_before_constant_additions =
                ([[F::zero(); N]; NUM_ROUNDS], [[F::zero(); N]; NUM_ROUNDS]);
            for r in 0..NUM_ROUNDS {
                for i in 0..N {
                    x[i] += &Self::ROUND_KEYS_X[r][i];
                    y[i] += &Self::ROUND_KEYS_Y[r][i];
                }
                mds.permute_in_place(x, y);
                for i in 0..N {
                    y[i] += &x[i];
                    x[i] += &y[i];
                }
                for i in 0..N {
                    x[i] -= &(Self::GENERATOR * (y[i].square()));
                    y[i] -= &x[i].pow(&alpha_inv);
                    x[i] += &(Self::GENERATOR * (y[i].square()) + Self::GENERATOR_INV);
                }

                intermediate_values_before_constant_additions.0[r] = *x;
                intermediate_values_before_constant_additions.1[r] = *y;
            }

            mds.permute_in_place(x, y);
            for i in 0..N {
                y[i] += &x[i];
                x[i] += &y[i];
            }

            trace
                .intermediate_values_before_constant_additions
                .push(intermediate_values_before_constant_additions);

            trace.after_permutation.push((*x, *y));
        };

        // initialize the internal state.
        let mut x = [F::zero(); N];
        let mut y = [F::zero(); N];
        for chunk in input.chunks_exact(2 * N - 1) {
            for i in 0..N {
                x[i] += &chunk[i];
            }
            for i in 0..(N - 1) {
                y[i] += &chunk[N + i];
            }

            anemoi_permutation_with_trace(&mut x, &mut y);
        }
        y[N - 1] += &sigma;

        if output_len <= N {
            trace.output.extend_from_slice(&x[..output_len])
        } else if output_len > N && output_len <= (2 * N - 1) {
            trace.output.extend_from_slice(&x);
            trace.output.extend_from_slice(&y[..output_len - N])
        } else if output_len > (2 * N - 1) {
            trace.output.extend_from_slice(&x);
            trace.output.extend_from_slice(&y[..N - 1]);

            let squeezing_times = output_len / (2 * N - 1) - 1;
            let remaining = output_len % (2 * N - 1);

            for _ in 0..squeezing_times {
                anemoi_permutation_with_trace(&mut x, &mut y);

                trace.output.extend_from_slice(&x);
                trace.output.extend_from_slice(&y[..N - 1]);
            }

            if remaining > 0 {
                anemoi_permutation_with_trace(&mut x, &mut y);

                let mut x = x.to_vec();
                x.extend_from_slice(&y);
                trace.output.extend_from_slice(&x[..remaining]);
            }
        }

        trace
    }

    /// Applies an Anemoi permutation to the state
    fn anemoi_permutation(x: &mut [F; N], y: &mut [F; N]) {
        let mds = MDSMatrix::<F, N>(Self::MDS_MATRIX);
        let alpha_inv = Self::get_alpha_inv();

        for r in 0..NUM_ROUNDS {
            for i in 0..N {
                x[i] += &Self::ROUND_KEYS_X[r][i];
                y[i] += &Self::ROUND_KEYS_Y[r][i];
            }
            mds.permute_in_place(x, y);
            for i in 0..N {
                y[i] += &x[i];
                x[i] += &y[i];
            }

            for i in 0..N {
                x[i] -= &(Self::GENERATOR * &(y[i].square()));
                y[i] -= &x[i].pow(&alpha_inv);
                x[i] += &(Self::GENERATOR * &(y[i].square()) + Self::GENERATOR_INV);
            }
        }
        mds.permute_in_place(x, y);
        for i in 0..N {
            y[i] += &x[i];
            x[i] += &y[i];
        }
    }
}
