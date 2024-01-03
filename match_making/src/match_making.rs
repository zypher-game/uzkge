use ark_ff::PrimeField;
use num_bigint::BigUint;
use num_integer::Integer;
use zplonk::{
    anemoi::{AnemoiJive, AnemoiVLHTrace},
    turboplonk::constraint_system::{TurboCS, VarIndex},
};

pub struct MatchMaking<const N: usize, F: PrimeField> {
    pub input_vars: Vec<VarIndex>,

    pub committed_input_var: VarIndex,
    pub committed_ouput_var: VarIndex,
    pub committed_trace: AnemoiVLHTrace<F, 2, 14>,

    pub random_number: F,
    pub random_number_var: VarIndex,

    pub output_vars: Vec<VarIndex>,
}

impl<const N: usize, F: PrimeField> MatchMaking<N, F> {
    pub fn new(
        input_vars: &[VarIndex],
        committed_input_var: VarIndex,
        committed_ouput_var: VarIndex,
        committed_trace: &AnemoiVLHTrace<F, 2, 14>,
        random_number: &F,
        random_number_var: VarIndex,
    ) -> Self {
        assert_eq!(input_vars.len(), N);

        Self {
            input_vars: input_vars.to_vec(),
            committed_input_var,
            committed_ouput_var,
            committed_trace: committed_trace.clone(),
            random_number: *random_number,
            random_number_var,
            output_vars: Vec::new(),
        }
    }

    pub fn generate_constraints<P: AnemoiJive<F, 2, 14>>(&mut self, cs: &mut TurboCS<F>) {
        let zero = F::zero();
        let one = F::one();
        let minus_one = one.neg();

        let mut indexes = Vec::new();
        let mut index_vars = Vec::new();
        for i in 1..=N {
            let index = F::from(i as u64);
            let index_var = cs.new_variable(index);
            cs.insert_constant_gate(index_var, index);
            indexes.push(index);
            index_vars.push(index_var)
        }

        cs.anemoi_variable_length_hash::<P>(
            &self.committed_trace,
            &[self.committed_input_var],
            self.committed_ouput_var,
        );

        let stream_cipher_trace = P::eval_stream_cipher_with_trace(
            &[self.committed_trace.input[0], self.random_number],
            N - 1,
        );
        let stream_cipher_trace_output_vars = stream_cipher_trace
            .output
            .iter()
            .map(|x| cs.new_variable(*x))
            .collect::<Vec<_>>();
        cs.anemoi_stream_cipher::<P>(
            &stream_cipher_trace,
            &[self.committed_input_var, self.random_number_var],
            &stream_cipher_trace_output_vars,
        );

        let mut output_vars = self.input_vars.clone();

        for i in 1..N {
            let n: BigUint = stream_cipher_trace.output[i - 1].into();
            let m = BigUint::from(i + 1);
            let (quotient, remainder) = n.div_rem(&m);
            let quotient = F::from(quotient);
            let remainder = F::from(remainder);
            let remainder_plus_one = remainder.add(one);

            let n_var = cs.new_variable(stream_cipher_trace.output[i - 1]);
            let quotient_var = cs.new_variable(quotient);
            let remainder_plus_one_var = cs.new_variable(remainder_plus_one);

            cs.push_add_selectors(F::from((i + 1) as u64), one, zero, zero);
            cs.push_mul_selectors(zero, zero);
            cs.push_constant_selector(minus_one);
            cs.push_out_selector(one);

            cs.wiring[0].push(quotient_var);
            cs.wiring[1].push(remainder_plus_one_var);
            cs.wiring[2].push(cs.zero_var());
            cs.wiring[3].push(cs.zero_var());
            cs.wiring[4].push(n_var);

            cs.finish_new_gate();

            let relative_indices = indexes
                .iter()
                .take(i + 1)
                .map(|x| x.sub(&remainder_plus_one))
                .collect::<Vec<F>>();

            let mut bits: Vec<F> = Vec::new();
            for x in relative_indices.iter() {
                if x.is_zero() {
                    bits.push(one);
                } else {
                    bits.push(zero);
                }
            }
            let bits_vars = bits.iter().map(|x| cs.new_variable(*x)).collect::<Vec<_>>();

            {
                // Enforce that the sum of bits equals 1.
                let mut sum_bits_var = cs.zero_var();
                for c in bits_vars.chunks(3) {
                    match c.len() {
                        3 => {
                            sum_bits_var = cs.linear_combine(
                                &[sum_bits_var, c[0], c[1], c[2]],
                                one,
                                one,
                                one,
                                one,
                            );
                            cs.attach_boolean_constraint_to_gate();
                        }

                        2 => {
                            sum_bits_var = cs.linear_combine(
                                &[sum_bits_var, c[0], c[1], cs.zero_var()],
                                one,
                                one,
                                one,
                                zero,
                            );
                            cs.attach_boolean_constraint_to_gate();
                        }

                        1 => {
                            sum_bits_var = cs.linear_combine(
                                &[sum_bits_var, c[0], cs.zero_var(), cs.zero_var()],
                                one,
                                one,
                                zero,
                                zero,
                            );
                            cs.attach_boolean_constraint_to_gate();
                        }

                        _ => unreachable!(),
                    }
                }
            }

            for i in 0..bits_vars.len() {
                cs.push_add_selectors(zero, zero, zero, zero);
                cs.push_mul_selectors(one, minus_one);
                cs.push_constant_selector(zero);
                cs.push_out_selector(zero);

                cs.wiring[0].push(index_vars[i]);
                cs.wiring[1].push(bits_vars[i]);
                cs.wiring[2].push(remainder_plus_one_var);
                cs.wiring[3].push(bits_vars[i]);
                cs.wiring[4].push(cs.zero_var());

                cs.finish_new_gate();
            }

            let output_i_var = output_vars[i];

            let bit_mul_output_vars = bits_vars
                .iter()
                .zip(output_vars.iter())
                .map(|(x, y)| cs.mul(*x, *y))
                .collect::<Vec<_>>();
            let mut swap_var = cs.zero_var();
            for c in bit_mul_output_vars.chunks(3) {
                match c.len() {
                    3 => {
                        swap_var =
                            cs.linear_combine(&[swap_var, c[0], c[1], c[2]], one, one, one, one);
                    }

                    2 => {
                        swap_var = cs.linear_combine(
                            &[swap_var, c[0], c[1], cs.zero_var()],
                            one,
                            one,
                            one,
                            zero,
                        );
                    }

                    1 => {
                        swap_var = cs.linear_combine(
                            &[swap_var, c[0], cs.zero_var(), cs.zero_var()],
                            one,
                            one,
                            zero,
                            zero,
                        );
                    }
                    _ => unreachable!(),
                }
            }
            output_vars[i] = swap_var;

            for j in 0..i {
                output_vars[j] = cs.select(output_vars[j], output_i_var, bits_vars[j])
            }
        }

        self.output_vars = output_vars;
    }
}
