use ark_ff::PrimeField;
use itertools::Itertools;

use crate::{plonk::constraint_system::TurboCS, shuffle::Permutation};

use super::CardVar;

impl<F: PrimeField> TurboCS<F> {
    /// Insert the 'shuffle' operation within the constraint system.
    pub fn shuffle_card(
        &mut self,
        card_vars: &[CardVar],
        permutation: &Permutation<F>,
    ) -> Vec<CardVar> {
        let n = permutation.len();
        assert_eq!(card_vars.len(), n);

        let zero = F::ZERO;
        let one = F::ONE;
        let zero_var = self.zero_var();
        let one_var = self.one_var();

        let mut permutation_matrix_vars = Vec::with_capacity(n);
        for x in permutation.get_matrix().iter() {
            let mut tmp = Vec::with_capacity(n);
            for y in x.iter() {
                tmp.push(self.new_variable(*y))
            }
            permutation_matrix_vars.push(tmp);
        }

        for x in permutation_matrix_vars.iter() {
            let mut sum_var = zero_var;
            for c in x.chunks(3) {
                match c.len() {
                    3 => {
                        sum_var =
                            self.linear_combine(&[sum_var, c[0], c[1], c[2]], one, one, one, one);
                        self.attach_boolean_constraint_to_gate();
                    }

                    2 => {
                        sum_var = self.linear_combine(
                            &[sum_var, c[0], c[1], zero_var],
                            one,
                            one,
                            one,
                            zero,
                        );
                        self.attach_boolean_constraint_to_gate();
                    }

                    1 => {
                        sum_var = self.linear_combine(
                            &[sum_var, c[0], zero_var, zero_var],
                            one,
                            one,
                            zero,
                            zero,
                        );
                        self.attach_boolean_constraint_to_gate();
                    }

                    _ => unreachable!(),
                }
            }

            self.equal(sum_var, one_var)
        }

        (0..n).for_each(|j| {
            let x = (0..n).map(|i| permutation_matrix_vars[i][j]).collect_vec();

            let mut sum_var = zero_var;
            for c in x.chunks(3) {
                match c.len() {
                    3 => {
                        sum_var =
                            self.linear_combine(&[sum_var, c[0], c[1], c[2]], one, one, one, one);
                    }

                    2 => {
                        sum_var = self.linear_combine(
                            &[sum_var, c[0], c[1], zero_var],
                            one,
                            one,
                            one,
                            zero,
                        );
                    }

                    1 => {
                        sum_var = self.linear_combine(
                            &[sum_var, c[0], zero_var, zero_var],
                            one,
                            one,
                            zero,
                            zero,
                        );
                    }

                    _ => unreachable!(),
                }
            }

            self.equal(sum_var, one_var)
        });

        let card_split_vars = (0..card_vars[0].len())
            .map(|i| card_vars.iter().map(|x| x[i]).collect_vec())
            .collect_vec();

        let mut permuted_card_vars = vec![];

        for permutation_var in permutation_matrix_vars.iter() {
            let mut permuted_card_var = CardVar::default();

            for (i, card_var) in card_split_vars.iter().enumerate() {
                let mut r_vars = vec![];

                for var in permutation_var.chunks(2).zip(card_var.chunks(2)) {
                    match var.0.len() {
                        2 => {
                            let a = self.witness[var.0[0]];
                            let b = self.witness[var.0[1]];
                            let c = self.witness[var.1[0]];
                            let d = self.witness[var.1[1]];
                            let r = a.mul(c).add(b.mul(d));
                            let r_var = self.new_variable(r);
                            r_vars.push(r_var);

                            self.push_add_selectors(zero, zero, zero, zero);
                            self.push_mul_selectors(one, one);
                            self.push_constant_selector(zero);
                            self.push_out_selector(one);

                            self.wiring[0].push(var.0[0]);
                            self.wiring[1].push(var.1[0]);
                            self.wiring[2].push(var.0[1]);
                            self.wiring[3].push(var.1[1]);
                            self.wiring[4].push(r_var);
                            self.finish_new_gate();
                        }

                        1 => {
                            let a = self.witness[var.0[0]];
                            let b = self.witness[var.1[0]];
                            let r = a.mul(b);
                            let r_var = self.new_variable(r);
                            r_vars.push(r_var);

                            self.push_add_selectors(zero, zero, zero, zero);
                            self.push_mul_selectors(one, one);
                            self.push_constant_selector(zero);
                            self.push_out_selector(one);

                            self.wiring[0].push(var.0[0]);
                            self.wiring[1].push(var.1[0]);
                            self.wiring[2].push(zero_var);
                            self.wiring[3].push(zero_var);
                            self.wiring[4].push(r_var);
                            self.finish_new_gate();
                        }

                        _ => unreachable!(),
                    }
                }

                let mut sum_var = zero_var;
                for c in r_vars.chunks(3) {
                    match c.len() {
                        3 => {
                            sum_var = self.linear_combine(
                                &[sum_var, c[0], c[1], c[2]],
                                one,
                                one,
                                one,
                                one,
                            );
                        }

                        2 => {
                            sum_var = self.linear_combine(
                                &[sum_var, c[0], c[1], zero_var],
                                one,
                                one,
                                one,
                                zero,
                            );
                        }

                        1 => {
                            sum_var = self.linear_combine(
                                &[sum_var, c[0], zero_var, zero_var],
                                one,
                                one,
                                zero,
                                zero,
                            );
                        }

                        _ => unreachable!(),
                    }
                }

                permuted_card_var.set(i, sum_var);
            }

            permuted_card_vars.push(permuted_card_var);
        }

        permuted_card_vars
    }
}
