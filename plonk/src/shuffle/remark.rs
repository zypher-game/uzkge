use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field};
use ark_std::rand::Rng;

use crate::turboplonk::constraint_system::turbo::N_WIRE_SELECTORS;

use super::trace::RemarkTrace;
use super::{Ciphertext, N_SELECT_BITS};

pub trait Remark<C: CurveGroup> {
    /// The paramater a of twisted Edwards curve.
    const COFF_A: C::BaseField;
    /// The paramater d of twisted Edwards curve.
    const COFF_D: C::BaseField;
    /// The number of iterations in scalar multiplication.
    const NUM_ITERATIONS: usize;

    /// Generate random bits for scalar.
    fn sample_random_scalar_bits<R: Rng>(rng: &mut R) -> Vec<[bool; N_WIRE_SELECTORS]> {
        let mut bits = Vec::with_capacity(Self::NUM_ITERATIONS);
        for _ in 0..Self::NUM_ITERATIONS {
            let tmp: [bool; N_WIRE_SELECTORS] = rng.gen();
            bits.push(tmp);
        }

        bits
    }

    /// Return the `generators_x` that have been preprocessed.
    fn get_preprocessed_generators_x() -> Vec<Vec<C::BaseField>>;

    /// Return the `generators_y` that have been preprocessed.
    fn get_preprocessed_generators_y() -> Vec<Vec<C::BaseField>>;

    /// Return the `generators_dxy` that have been preprocessed.
    fn get_preprocessed_generators_dxy() -> Vec<Vec<C::BaseField>>;

    /// Generate generators.
    fn crate_generators() -> Vec<Vec<C>> {
        let mut generators = Vec::with_capacity(Self::NUM_ITERATIONS);

        let mut g = C::generator();
        for _ in 0..Self::NUM_ITERATIONS {
            let mut generator_segment = Vec::with_capacity(N_SELECT_BITS);
            let mut segment = g.clone();

            for _ in 0..N_SELECT_BITS {
                generator_segment.push(segment);
                segment.add_assign(g);
            }

            for _ in 0..N_SELECT_BITS {
                g.double_in_place();
            }

            generators.push(generator_segment)
        }

        generators
    }

    /// Generate public keys.
    fn crate_public_keys(pk: &C) -> Vec<Vec<C>> {
        let mut public_keys = Vec::with_capacity(Self::NUM_ITERATIONS);

        let mut pk = pk.clone();
        for _ in 0..Self::NUM_ITERATIONS {
            let mut public_key_segment = Vec::with_capacity(N_SELECT_BITS);
            let mut segment = pk.clone();

            for _ in 0..N_SELECT_BITS {
                public_key_segment.push(segment);
                segment.add_assign(pk);
            }

            for _ in 0..N_SELECT_BITS {
                pk.double_in_place();
            }

            public_keys.push(public_key_segment)
        }

        public_keys
    }

    /// Evaluate the remark operation, with a random scalar.
    fn eval_remark(
        input: &Ciphertext<C>,
        r_bits: &[[bool; N_WIRE_SELECTORS]],
        pk: &C,
    ) -> Ciphertext<C> {
        assert_eq!(r_bits.len(), Self::NUM_ITERATIONS);

        let generators = Self::crate_generators();
        let pks = Self::crate_public_keys(pk);

        let mut c1 = input.get_first(); /* r \cdot G */
        let mut c2 = input.get_second(); /* M + r \cdot PK */

        for (bits, (generator, pk)) in r_bits.iter().zip(generators.iter().zip(pks.iter())) {
            match (bits[0], bits[1], bits[2]) {
                (false, false, false) => {
                    c1.add_assign(generator[0].neg());
                    c2.add_assign(pk[0].neg());
                }
                (false, false, true) => {
                    c1.add_assign(generator[0]);
                    c2.add_assign(pk[0]);
                }
                (true, false, false) => {
                    c1.add_assign(generator[1].neg());
                    c2.add_assign(pk[1].neg());
                }
                (true, false, true) => {
                    c1.add_assign(generator[1]);
                    c2.add_assign(pk[1]);
                }
                (false, true, false) => {
                    c1.add_assign(generator[2].neg());
                    c2.add_assign(pk[2].neg());
                }
                (false, true, true) => {
                    c1.add_assign(generator[2]);
                    c2.add_assign(pk[2]);
                }
                (true, true, false) => {
                    c1.add_assign(generator[3].neg());
                    c2.add_assign(pk[3].neg());
                }
                (true, true, true) => {
                    c1.add_assign(generator[3]);
                    c2.add_assign(pk[3]);
                }
            }
        }

        Ciphertext::new(c1, c2)
    }

    /// Evaluate the remark operation with trace, with a random scalar.
    fn eval_remark_with_trace(
        input: &Ciphertext<C>,
        r_bits: &[[bool; N_WIRE_SELECTORS]],
        pk: &C,
    ) -> RemarkTrace<C::BaseField> {
        assert_eq!(r_bits.len(), Self::NUM_ITERATIONS);
        let zero = C::BaseField::ZERO;
        let one = C::BaseField::ONE;
        let minus_one = -one;

        let mut trace = RemarkTrace::default();
        trace.n_round = Self::NUM_ITERATIONS;

        let generators = Self::crate_generators();
        let pks = Self::crate_public_keys(pk);

        let mut c1 = input.get_first(); /* r \cdot G */
        let mut c2 = input.get_second(); /* M + r \cdot PK */

        let mut field_bits = Vec::with_capacity(Self::NUM_ITERATIONS);
        let mut intermediate_values = Vec::with_capacity(Self::NUM_ITERATIONS);

        for (bits, (generator, pk)) in r_bits.iter().zip(generators.iter().zip(pks.iter())) {
            match (bits[0], bits[1], bits[2]) {
                (false, false, false) => {
                    c1.add_assign(generator[0].neg());
                    c2.add_assign(pk[0].neg());

                    field_bits.push([zero, zero, minus_one]);
                }
                (false, false, true) => {
                    c1.add_assign(generator[0]);
                    c2.add_assign(pk[0]);

                    field_bits.push([zero, zero, one]);
                }
                (true, false, false) => {
                    c1.add_assign(generator[1].neg());
                    c2.add_assign(pk[1].neg());

                    field_bits.push([one, zero, minus_one]);
                }
                (true, false, true) => {
                    c1.add_assign(generator[1]);
                    c2.add_assign(pk[1]);

                    field_bits.push([one, zero, one]);
                }
                (false, true, false) => {
                    c1.add_assign(generator[2].neg());
                    c2.add_assign(pk[2].neg());

                    field_bits.push([zero, one, minus_one]);
                }
                (false, true, true) => {
                    c1.add_assign(generator[2]);
                    c2.add_assign(pk[2]);

                    field_bits.push([zero, one, one]);
                }
                (true, true, false) => {
                    c1.add_assign(generator[3].neg());
                    c2.add_assign(pk[3].neg());

                    field_bits.push([one, one, minus_one]);
                }
                (true, true, true) => {
                    c1.add_assign(generator[3]);
                    c2.add_assign(pk[3]);

                    field_bits.push([one, one, one]);
                }
            }

            let (c1_x, c1_y) = c1
                .into_affine()
                .xy()
                .unwrap_or((C::BaseField::ZERO, C::BaseField::ONE));
            let (c2_x, c2_y) = c2
                .into_affine()
                .xy()
                .unwrap_or((C::BaseField::ZERO, C::BaseField::ONE));
            intermediate_values.push([c2_x, c2_y, c1_x, c1_y]);
        }

        trace.bits = field_bits;
        trace.intermediate_values = intermediate_values;
        trace.output = *trace.intermediate_values.last().unwrap();

        trace
    }
}
