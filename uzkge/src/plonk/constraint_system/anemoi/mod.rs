use ark_ff::PrimeField;

use crate::{
    anemoi::{AnemoiJive, AnemoiStreamCipherTrace, AnemoiVLHTrace, N_ANEMOI_ROUNDS},
    plonk::constraint_system::{TurboCS, VarIndex},
};

impl<F: PrimeField> TurboCS<F> {
    /// Create constraints for the Anemoi permutation.
    fn anemoi_permutation_round<P: AnemoiJive<F, 2usize, N_ANEMOI_ROUNDS>>(
        &mut self,
        input_var: &([VarIndex; 2], [VarIndex; 2]),
        output_var: &([Option<VarIndex>; 2], [Option<VarIndex>; 2]),
        intermediate_val: &([[F; 2]; N_ANEMOI_ROUNDS], [[F; 2]; N_ANEMOI_ROUNDS]),
        checksum: Option<F>,
        salt: Option<F>,
    ) -> Option<VarIndex> {
        let zero = F::ZERO;
        let one = F::ONE;
        let zero_var = self.zero_var();

        // Allocate the intermediate values
        // (the last line of the intermediate values is the output of the last round
        // before the final linear layer)
        let mut intermediate_var = (
            [[zero_var; 2]; N_ANEMOI_ROUNDS],
            [[zero_var; 2]; N_ANEMOI_ROUNDS],
        );

        for r in 0..N_ANEMOI_ROUNDS {
            intermediate_var.0[r][0] = self.new_variable(intermediate_val.0[r][0]);
            intermediate_var.0[r][1] = self.new_variable(intermediate_val.0[r][1]);
            intermediate_var.1[r][0] = self.new_variable(intermediate_val.1[r][0]);
            intermediate_var.1[r][1] = self.new_variable(intermediate_val.1[r][1]);
        }

        // Create the first gate --- which puts the initial value
        if salt.is_some() {
            self.push_add_selectors(zero, zero, zero, one);
            self.push_constant_selector(salt.unwrap().neg());
        } else {
            self.push_add_selectors(zero, zero, zero, zero);
            self.push_constant_selector(zero);
        }

        self.push_mul_selectors(zero, zero);
        self.push_ecc_selector(zero);
        self.push_out_selector(zero);

        self.wiring[0].push(input_var.0[0]); // a_0
        self.wiring[1].push(input_var.0[1]); // b_0
        self.wiring[2].push(input_var.1[0]); // c_0
        self.wiring[3].push(input_var.1[1]); // d_0
        self.wiring[4].push(intermediate_var.1[0][1]); // d_1
        self.finish_new_gate();

        self.attach_anemoi_jive_constraints_to_gate();

        // Create the remaining 13 gates
        for r in 1..N_ANEMOI_ROUNDS {
            self.push_add_selectors(zero, zero, zero, zero);
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_ecc_selector(zero);
            self.push_out_selector(zero);

            self.wiring[0].push(intermediate_var.0[r - 1][0]); // a_i
            self.wiring[1].push(intermediate_var.0[r - 1][1]); // b_i
            self.wiring[2].push(intermediate_var.1[r - 1][0]); // c_i
            self.wiring[3].push(intermediate_var.1[r - 1][1]); // d_i
            self.wiring[4].push(intermediate_var.1[r][1]); // d_{i+1}

            self.finish_new_gate();
        }

        if output_var.0[0].is_some() {
            let var = output_var.0[0].unwrap();

            self.push_add_selectors(
                P::MDS_MATRIX[0][0].double(),
                P::MDS_MATRIX[0][1].double(),
                P::MDS_MATRIX[0][1],
                P::MDS_MATRIX[0][0],
            );
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_ecc_selector(zero);
            self.push_out_selector(one);

            self.wiring[0].push(intermediate_var.0[13][0]); // a_r
            self.wiring[1].push(intermediate_var.0[13][1]); // b_r
            self.wiring[2].push(intermediate_var.1[13][0]); // c_r
            self.wiring[3].push(intermediate_var.1[13][1]); // d_r
            self.wiring[4].push(var); // a_final

            self.finish_new_gate();
        }

        if output_var.0[1].is_some() {
            let var = output_var.0[1].unwrap();

            self.push_add_selectors(
                P::MDS_MATRIX[1][0].double(),
                P::MDS_MATRIX[1][1].double(),
                P::MDS_MATRIX[1][1],
                P::MDS_MATRIX[1][0],
            );
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_ecc_selector(zero);
            self.push_out_selector(one);

            self.wiring[0].push(intermediate_var.0[13][0]); // a_r
            self.wiring[1].push(intermediate_var.0[13][1]); // b_r
            self.wiring[2].push(intermediate_var.1[13][0]); // c_r
            self.wiring[3].push(intermediate_var.1[13][1]); // d_r
            self.wiring[4].push(var); // b_final

            self.finish_new_gate();
        }

        if output_var.1[0].is_some() {
            let var = output_var.1[0].unwrap();

            self.push_add_selectors(
                P::MDS_MATRIX[0][0],
                P::MDS_MATRIX[0][1],
                P::MDS_MATRIX[0][1],
                P::MDS_MATRIX[0][0],
            );
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_ecc_selector(zero);
            self.push_out_selector(one);

            self.wiring[0].push(intermediate_var.0[13][0]); // a_r
            self.wiring[1].push(intermediate_var.0[13][1]); // b_r
            self.wiring[2].push(intermediate_var.1[13][0]); // c_r
            self.wiring[3].push(intermediate_var.1[13][1]); // d_r
            self.wiring[4].push(var); // c_final

            self.finish_new_gate();
        }

        if output_var.1[1].is_some() {
            let var = output_var.1[1].unwrap();

            self.push_add_selectors(
                P::MDS_MATRIX[1][0],
                P::MDS_MATRIX[1][1],
                P::MDS_MATRIX[1][1],
                P::MDS_MATRIX[1][0],
            );
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_ecc_selector(zero);
            self.push_out_selector(one);

            self.wiring[0].push(intermediate_var.0[13][0]); // a_r
            self.wiring[1].push(intermediate_var.0[13][1]); // b_r
            self.wiring[2].push(intermediate_var.1[13][0]); // c_r
            self.wiring[3].push(intermediate_var.1[13][1]); // d_r
            self.wiring[4].push(var); // d_final

            self.finish_new_gate();
        }

        if checksum.is_some() {
            let var = self.new_variable(checksum.unwrap());

            self.push_add_selectors(
                (P::MDS_MATRIX[0][0] + P::MDS_MATRIX[1][0]).double()
                    + (P::MDS_MATRIX[0][0] + P::MDS_MATRIX[1][0]),
                (P::MDS_MATRIX[0][1] + P::MDS_MATRIX[1][1]).double()
                    + (P::MDS_MATRIX[0][1] + P::MDS_MATRIX[1][1]),
                (P::MDS_MATRIX[0][1] + P::MDS_MATRIX[1][1]).double(),
                (P::MDS_MATRIX[0][0] + P::MDS_MATRIX[1][0]).double(),
            );
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_ecc_selector(zero);
            self.push_out_selector(one);

            self.wiring[0].push(intermediate_var.0[13][0]); // a_r
            self.wiring[1].push(intermediate_var.0[13][1]); // b_r
            self.wiring[2].push(intermediate_var.1[13][0]); // c_r
            self.wiring[3].push(intermediate_var.1[13][1]); // d_r
            self.wiring[4].push(var); // sum

            self.finish_new_gate();

            Some(var)
        } else {
            None
        }
    }

    /// Create constraints for the Anemoi variable length hash function.
    pub fn anemoi_variable_length_hash<P: AnemoiJive<F, 2usize, N_ANEMOI_ROUNDS>>(
        &mut self,
        trace: &AnemoiVLHTrace<F, 2, N_ANEMOI_ROUNDS>,
        input_var: &[VarIndex],
        output_var: VarIndex,
    ) {
        assert_eq!(input_var.len(), trace.input.len());

        let mut input_var = input_var.to_vec();
        let one_var = self.one_var();
        let zero_var = self.zero_var();

        if input_var.len() % (2 * 2 - 1) != 0 || input_var.is_empty() {
            input_var.push(one_var);
            if input_var.len() % (2 * 2 - 1) != 0 {
                input_var.extend_from_slice(
                    &[zero_var].repeat(2 * 2 - 1 - (input_var.len() % (2 * 2 - 1))),
                );
            }
        }

        assert_eq!(
            input_var.len(),
            trace.before_permutation.len() * (2 * 2 - 1)
        );

        // initialize the internal state.
        let chunks = input_var
            .chunks_exact(2 * 2 - 1)
            .map(|x| x.to_vec())
            .collect::<Vec<Vec<VarIndex>>>();
        let num_chunks = chunks.len();

        let mut x_var = [chunks[0][0], chunks[0][1]];
        let mut y_var = [chunks[0][2], zero_var];

        if num_chunks == 1 {
            self.anemoi_permutation_round::<P>(
                &(x_var, y_var),
                &([Some(output_var), None], [None, None]),
                &trace.intermediate_values_before_constant_additions[0],
                None,
                None,
            );
        } else {
            let mut new_x_var = [
                self.new_variable(trace.after_permutation[0].0[0]),
                self.new_variable(trace.after_permutation[0].0[1]),
            ];

            let mut new_y_var = [
                self.new_variable(trace.after_permutation[0].1[0]),
                self.new_variable(trace.after_permutation[0].1[1]),
            ];

            self.anemoi_permutation_round::<P>(
                &(x_var, y_var),
                &(
                    [Some(new_x_var[0]), Some(new_x_var[1])],
                    [Some(new_y_var[0]), Some(new_y_var[1])],
                ),
                &trace.intermediate_values_before_constant_additions[0],
                None,
                None,
            );

            for rr in 1..num_chunks - 1 {
                x_var = new_x_var;
                y_var = new_y_var;

                x_var[0] = self.add(x_var[0], chunks[rr][0]);
                x_var[1] = self.add(x_var[1], chunks[rr][1]);
                y_var[0] = self.add(y_var[0], chunks[rr][2]);

                new_x_var = [
                    self.new_variable(trace.after_permutation[rr].0[0]),
                    self.new_variable(trace.after_permutation[rr].0[1]),
                ];

                new_y_var = [
                    self.new_variable(trace.after_permutation[rr].1[0]),
                    self.new_variable(trace.after_permutation[rr].1[1]),
                ];

                self.anemoi_permutation_round::<P>(
                    &(x_var, y_var),
                    &(
                        [Some(new_x_var[0]), Some(new_x_var[1])],
                        [Some(new_y_var[0]), Some(new_y_var[1])],
                    ),
                    &trace.intermediate_values_before_constant_additions[rr],
                    None,
                    None,
                );
            }

            // last round
            {
                x_var = new_x_var;
                y_var = new_y_var;

                x_var[0] = self.add(x_var[0], chunks[num_chunks - 1][0]);
                x_var[1] = self.add(x_var[1], chunks[num_chunks - 1][1]);
                y_var[0] = self.add(y_var[0], chunks[num_chunks - 1][2]);

                self.anemoi_permutation_round::<P>(
                    &(x_var, y_var),
                    &([Some(output_var), None], [None, None]),
                    &trace.intermediate_values_before_constant_additions[num_chunks - 1],
                    None,
                    None,
                );
            }
        }
    }

    /// Create constraints for the Anemoi stream cipher
    pub fn anemoi_stream_cipher<P: AnemoiJive<F, 2usize, 14usize>>(
        &mut self,
        trace: &AnemoiStreamCipherTrace<F, 2, 14>,
        input_var: &[VarIndex],
        output_var: &[VarIndex],
    ) {
        assert_eq!(input_var.len(), trace.input.len());
        assert_eq!(output_var.len(), trace.output.len());

        let mut input_var = input_var.to_vec();
        let mut output_var = output_var.iter().map(|x| Some(*x)).collect::<Vec<_>>();
        let one_var = self.one_var();
        let zero_var = self.zero_var();

        if output_var.len() % (2 * 2 - 1) != 0 {
            output_var
                .extend_from_slice(&[None].repeat(2 * 2 - 1 - (output_var.len() % (2 * 2 - 1))));
        }
        let output_chunks = output_var
            .chunks_exact(2 * 2 - 1)
            .map(|x| x.to_vec())
            .collect::<Vec<Vec<_>>>();
        let num_output_chunks: usize = output_chunks.len();

        let sigma_var = if input_var.len() % (2 * 2 - 1) == 0 && !input_var.is_empty() {
            one_var
        } else {
            input_var.push(one_var);
            if input_var.len() % (2 * 2 - 1) != 0 {
                input_var.extend_from_slice(
                    &[zero_var].repeat(2 * 2 - 1 - (input_var.len() % (2 * 2 - 1))),
                );
            }
            zero_var
        };

        assert_eq!(
            input_var.len() + output_var.len() - (2 * 2 - 1),
            trace.before_permutation.len() * (2 * 2 - 1)
        );

        // initialize the internal state.
        let input_chunks = input_var
            .chunks_exact(2 * 2 - 1)
            .map(|x| x.to_vec())
            .collect::<Vec<Vec<VarIndex>>>();
        let num_input_chunks = input_chunks.len();

        let mut x_var = [input_chunks[0][0], input_chunks[0][1]];
        let mut y_var = [input_chunks[0][2], zero_var];

        if num_input_chunks == 1 && num_output_chunks == 1 {
            self.anemoi_permutation_round::<P>(
                &(x_var, y_var),
                &(
                    [output_chunks[0][0], output_chunks[0][1]],
                    [output_chunks[0][2], None],
                ),
                &trace.intermediate_values_before_constant_additions[0],
                None,
                None,
            );
        } else if num_input_chunks == 1 && num_output_chunks > 1 {
            self.anemoi_permutation_round::<P>(
                &(x_var, y_var),
                &(
                    [output_chunks[0][0], output_chunks[0][1]],
                    [output_chunks[0][2], None],
                ),
                &trace.intermediate_values_before_constant_additions[0],
                None,
                None,
            );

            let mut new_x_var = [
                self.new_variable(trace.after_permutation[0].0[0]),
                self.new_variable(trace.after_permutation[0].0[1]),
            ];

            let mut new_y_var = [
                self.new_variable(trace.after_permutation[0].1[0]),
                self.new_variable(trace.after_permutation[0].1[1]),
            ];
            new_y_var[1] = self.add(new_y_var[1], sigma_var);

            // the squeezing round
            for (rr, output_chunk) in output_chunks
                .iter()
                .enumerate()
                .take(num_output_chunks)
                .skip(1)
            {
                x_var = new_x_var;
                y_var = new_y_var;

                if rr != num_output_chunks - 1 {
                    new_x_var = [
                        self.new_variable(trace.after_permutation[rr].0[0]),
                        self.new_variable(trace.after_permutation[rr].0[1]),
                    ];

                    new_y_var = [
                        self.new_variable(trace.after_permutation[rr].1[0]),
                        self.new_variable(trace.after_permutation[rr].1[1]),
                    ];
                }

                self.anemoi_permutation_round::<P>(
                    &(x_var, y_var),
                    &([output_chunk[0], output_chunk[1]], [output_chunk[2], None]),
                    &trace.intermediate_values_before_constant_additions[rr],
                    None,
                    None,
                );
            }
        } else if num_input_chunks > 1 {
            let mut new_x_var = [
                self.new_variable(trace.after_permutation[0].0[0]),
                self.new_variable(trace.after_permutation[0].0[1]),
            ];

            let mut new_y_var = [
                self.new_variable(trace.after_permutation[0].1[0]),
                self.new_variable(trace.after_permutation[0].1[1]),
            ];

            self.anemoi_permutation_round::<P>(
                &(x_var, y_var),
                &(
                    [Some(new_x_var[0]), Some(new_x_var[1])],
                    [Some(new_y_var[0]), Some(new_y_var[1])],
                ),
                &trace.intermediate_values_before_constant_additions[0],
                None,
                None,
            );

            for (rr, input_chunk) in input_chunks
                .iter()
                .enumerate()
                .take(num_input_chunks - 1)
                .skip(1)
            {
                x_var = new_x_var;
                y_var = new_y_var;

                x_var[0] = self.add(x_var[0], input_chunk[0]);
                x_var[1] = self.add(x_var[1], input_chunk[1]);
                y_var[0] = self.add(y_var[0], input_chunk[2]);

                new_x_var = [
                    self.new_variable(trace.after_permutation[rr].0[0]),
                    self.new_variable(trace.after_permutation[rr].0[1]),
                ];

                new_y_var = [
                    self.new_variable(trace.after_permutation[rr].1[0]),
                    self.new_variable(trace.after_permutation[rr].1[1]),
                ];

                self.anemoi_permutation_round::<P>(
                    &(x_var, y_var),
                    &(
                        [Some(new_x_var[0]), Some(new_x_var[1])],
                        [Some(new_y_var[0]), Some(new_y_var[1])],
                    ),
                    &trace.intermediate_values_before_constant_additions[rr],
                    None,
                    None,
                );
            }

            // last round of absorption
            {
                x_var = new_x_var;
                y_var = new_y_var;

                x_var[0] = self.add(x_var[0], input_chunks[num_input_chunks - 1][0]);
                x_var[1] = self.add(x_var[1], input_chunks[num_input_chunks - 1][1]);
                y_var[0] = self.add(y_var[0], input_chunks[num_input_chunks - 1][2]);

                if num_output_chunks > 1 {
                    new_x_var = [
                        self.new_variable(trace.after_permutation[num_input_chunks - 1].0[0]),
                        self.new_variable(trace.after_permutation[num_input_chunks - 1].0[1]),
                    ];

                    new_y_var = [
                        self.new_variable(trace.after_permutation[num_input_chunks - 1].1[0]),
                        self.new_variable(trace.after_permutation[num_input_chunks - 1].1[1]),
                    ];
                    new_y_var[1] = self.add(new_y_var[1], sigma_var);
                }

                self.anemoi_permutation_round::<P>(
                    &(x_var, y_var),
                    &(
                        [output_chunks[0][0], output_chunks[0][1]],
                        [output_chunks[0][2], None],
                    ),
                    &trace.intermediate_values_before_constant_additions[num_input_chunks - 1],
                    None,
                    None,
                );
            }

            // the squeezing round
            for (rr, output_chunk) in output_chunks
                .iter()
                .enumerate()
                .take(num_output_chunks)
                .skip(1)
            {
                x_var = new_x_var;
                y_var = new_y_var;

                if rr != num_output_chunks - 1 {
                    new_x_var = [
                        self.new_variable(trace.after_permutation[rr - 1 + num_input_chunks].0[0]),
                        self.new_variable(trace.after_permutation[rr - 1 + num_input_chunks].0[1]),
                    ];

                    new_y_var = [
                        self.new_variable(trace.after_permutation[rr - 1 + num_input_chunks].1[0]),
                        self.new_variable(trace.after_permutation[rr - 1 + num_input_chunks].1[1]),
                    ];
                }

                self.anemoi_permutation_round::<P>(
                    &(x_var, y_var),
                    &([output_chunk[0], output_chunk[1]], [output_chunk[2], None]),
                    &trace.intermediate_values_before_constant_additions[rr - 1 + num_input_chunks],
                    None,
                    None,
                );
            }
        }
    }
}

#[cfg(test)]
mod test_bn254 {
    use ark_bn254::Fr;

    use crate::{
        anemoi::{AnemoiJive, AnemoiJive254},
        plonk::constraint_system::TurboCS,
    };

    #[test]
    fn test_anemoi_variable_length_hash_constraint_system() {
        let trace = AnemoiJive254::eval_variable_length_hash_with_trace(&[
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ]);

        let mut cs = TurboCS::new();
        cs.load_anemoi_parameters::<AnemoiJive254>();

        let one = cs.new_variable(Fr::from(1u64));
        let two = cs.new_variable(Fr::from(2u64));
        let three = cs.new_variable(Fr::from(3u64));
        let four = cs.new_variable(Fr::from(4u64));

        let output_var = cs.new_variable(trace.output);

        let _ = cs.anemoi_variable_length_hash::<AnemoiJive254>(
            &trace,
            &[one, two, three, four],
            output_var,
        );

        let witness = cs.get_and_clear_witness();
        cs.verify_witness(&witness, &[]).unwrap();
    }

    #[test]
    fn test_anemoi_stream_cipher() {
        for output_len in 1..=7 {
            // There are two main test cases for input:
            // The first one is when the input length is 3 and sigma is equal to 1,
            // The second one is when the input length is 4 and sigma is equal to 0.
            for input_len in [3, 4u64] {
                let mut input = vec![];
                for i in 0..input_len {
                    input.push(Fr::from(i + 1));
                }
                let trace = AnemoiJive254::eval_stream_cipher_with_trace(&input, output_len);

                let mut cs = TurboCS::new();
                cs.load_anemoi_parameters::<AnemoiJive254>();

                let mut input_var = vec![];
                for i in input {
                    input_var.push(cs.new_variable(i))
                }

                let mut output_var = vec![];
                for o in &trace.output {
                    output_var.push(cs.new_variable(o.clone()))
                }

                let _ = cs.anemoi_stream_cipher::<AnemoiJive254>(&trace, &input_var, &output_var);
                let witness = cs.get_and_clear_witness();
                cs.verify_witness(&witness, &[]).unwrap();
            }
        }
    }
}
