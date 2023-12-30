use ark_ff::PrimeField;
use itertools::Itertools;

use crate::{
    shuffle::RemarkTrace,
    turboplonk::constraint_system::{turbo::N_WIRE_SELECTORS, TurboCS},
};

use super::CardVar;

impl<F: PrimeField> TurboCS<F> {
    /// Insert the 'remark' operation within the constraint system.
    pub fn eval_card_remark(&mut self, trace: &RemarkTrace<F>, input_var: &CardVar) -> CardVar {
        assert_eq!(trace.bits.len(), trace.n_round);
        assert_eq!(trace.intermediate_values.len(), trace.n_round);
        assert_eq!(self.n_iteration_shuffle_scalar_mul, trace.n_round);

        // Wire selector variables are not allocated in the constraint system,
        // because they do not have copy constraints.
        let bits = (0..N_WIRE_SELECTORS)
            .map(|i| trace.bits.iter().map(|x| x[i]).collect_vec())
            .collect_vec();
        self.attach_shuffle_remark_constraints_to_gate(bits.try_into().unwrap());

        let mut intermediate_value_vars = Vec::with_capacity(trace.n_round);
        for values in trace.intermediate_values.iter() {
            let mut vars = vec![];
            for x in values.iter() {
                vars.push(self.new_variable(*x));
            }
            intermediate_value_vars.push(vars);
        }

        let zero = F::zero();

        {
            //  Create gates for input values.
            self.push_add_selectors(zero, zero, zero, zero);
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_out_selector(zero);

            self.wiring[0].push(input_var.get_first_x()); // input_0
            self.wiring[1].push(input_var.get_first_y()); // input_1
            self.wiring[2].push(input_var.get_second_x()); // input_2
            self.wiring[3].push(input_var.get_second_y()); // input_3
            self.wiring[4].push(intermediate_value_vars[0][3]); // g_y_0

            self.finish_new_gate();
        }

        //  Create gates for all intermediate values except the last one.
        for r in 0..trace.n_round - 1 {
            self.push_add_selectors(zero, zero, zero, zero);
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_out_selector(zero);

            self.wiring[0].push(intermediate_value_vars[r][0]); // pk_x_r
            self.wiring[1].push(intermediate_value_vars[r][1]); // pk_y_r
            self.wiring[2].push(intermediate_value_vars[r][2]); // g_x_r
            self.wiring[3].push(intermediate_value_vars[r][3]); // g_y_r
            self.wiring[4].push(intermediate_value_vars[r + 1][3]); // g_y_{r+1}

            self.finish_new_gate();
        }

        //  Create the last gate with its output wire equal to 0.
        {
            self.push_add_selectors(zero, zero, zero, zero);
            self.push_mul_selectors(zero, zero);
            self.push_constant_selector(zero);
            self.push_out_selector(zero);

            self.wiring[0].push(intermediate_value_vars[trace.n_round - 1][0]); // pk_x_{r+1}
            self.wiring[1].push(intermediate_value_vars[trace.n_round - 1][1]); // pk_y_{r+1}
            self.wiring[2].push(intermediate_value_vars[trace.n_round - 1][2]); // g_x_{r+1}
            self.wiring[3].push(intermediate_value_vars[trace.n_round - 1][3]); // g_y_{r+1}
            self.wiring[4].push(self.zero_var()); // zero

            self.finish_new_gate();
        }

        CardVar::new(
            &intermediate_value_vars[trace.n_round - 1]
                .clone()
                .try_into()
                .unwrap(),
        )
    }
}

#[cfg(test)]
mod test {
    use ark_ec::PrimeGroup;
    use ark_ed_on_bn254::{EdwardsProjective, Fr};
    use ark_std::{rand::SeedableRng, UniformRand};
    use rand_chacha::ChaChaRng;

    use crate::{
        shuffle::{BabyJubjubShuffle, Ciphertext, Remark},
        turboplonk::constraint_system::TurboCS,
    };

    #[test]
    fn test_remark_constraint_system() {
        let mut prng = ChaChaRng::from_entropy();

        let secret = Fr::rand(&mut prng);
        let public = EdwardsProjective::generator() * secret;

        let m = EdwardsProjective::rand(&mut prng);
        let input = Ciphertext::encrypt(&mut prng, &m, &public);

        let bits = BabyJubjubShuffle::sample_random_scalar_bits(&mut prng);
        let trace = BabyJubjubShuffle::eval_remark_with_trace(&input, &bits, &public);

        let mut cs = TurboCS::new();
        cs.load_shuffle_remark_parameters::<_, BabyJubjubShuffle>(&public);

        let input_vars = cs.new_card_variable(&input);
        let output_vars = cs.eval_card_remark(&trace, &input_vars);
        cs.prepare_pi_card_variable(&output_vars);

        let witness = cs.get_and_clear_witness();
        cs.verify_witness(&witness, &trace.output).unwrap();
    }
}
