use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};

#[cfg(feature = "debug")]
use ark_std::collections::HashMap;

use crate::{
    anemoi::{AnemoiJive, N_ANEMOI_ROUNDS},
    errors::UzkgeError,
    shuffle::Remark,
    plonk::constraint_system::{ConstraintSystem, CsIndex, VarIndex},
    utils::serialization::{ark_deserialize, ark_serialize},
};

/// The wires number of a gate in Turbo CS.
pub const N_WIRES_PER_GATE: usize = 5;

///  The selectors number related to shuffle in Turbo CS.
pub const N_SHUFFLE_RELATED_SELECTORS: usize = 24;

/// The selectors number in Turbo CS.
pub const N_SELECTORS: usize = 8;

/// The wire selectors number in Turbo CS.
pub const N_WIRE_SELECTORS: usize = 3;

/// Turbo PLONK Constraint System.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TurboCS<F: PrimeField> {
    /// the selectors of the circuit.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub selectors: Vec<Vec<F>>,
    /// the wiring of the circuit.
    pub wiring: [Vec<VarIndex>; N_WIRES_PER_GATE],
    /// the paramater a of twisted Edwards curve.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub edwards_a: F,
    /// the x-coordinate of public keys related to shuffle..
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub shuffle_public_keys_x: Vec<Vec<F>>,
    /// the y-coordinate system of public keys related to shuffle.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub shuffle_public_keys_y: Vec<Vec<F>>,
    /// the dxy of public keys related to shuffle equals the product of the x-coordinate
    ///  and the y-coordinate multiplied by the coefficient D.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub shuffle_public_keys_dxy: Vec<Vec<F>>,
    /// the x-coordinate of generators related to shuffle..
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub shuffle_generators_x: Vec<Vec<F>>,
    /// the y-coordinate of generators related to shuffle..
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub shuffle_generators_y: Vec<Vec<F>>,
    /// the dxy of generators related to shuffle equals the product of the x-coordinate
    /// and the y-coordinate multiplied by the coefficient D.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub shuffle_generators_dxy: Vec<Vec<F>>,
    /// the first part of the Anemoi preprocessed round keys.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub anemoi_preprocessed_round_keys_x: [[F; 2]; N_ANEMOI_ROUNDS],
    /// the second part of the Anemoi preprocessed round keys.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub anemoi_preprocessed_round_keys_y: [[F; 2]; N_ANEMOI_ROUNDS],
    /// the Anemoi generator.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub anemoi_generator: F,
    /// the Anemoi generator's inverse.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub anemoi_generator_inv: F,
    /// the gates with Anemoi constraints.
    pub anemoi_constraints_indices: Vec<CsIndex>,
    /// the number of iterations required for scalar multiplication in the shuffle constraint system.
    pub n_iteration_shuffle_scalar_mul: usize,
    /// the number of variable.
    pub num_vars: usize,
    /// the size of circuit.
    pub size: usize,
    /// the public constraint variables indices.
    pub public_vars_constraint_indices: Vec<CsIndex>,
    /// the public witness variables indices.
    pub public_vars_witness_indices: Vec<VarIndex>,
    /// the gates with boolean constraint.
    pub boolean_constraint_indices: Vec<CsIndex>,
    /// the gates with shuffle remark constraint.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub shuffle_remark_constraint_indices: Vec<(CsIndex, [Vec<F>; N_WIRE_SELECTORS])>,
    /// only for verifier use.
    pub verifier_only: bool,
    /// A private witness for the circuit, cleared after computing a proof.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub witness: Vec<F>,
    /// record witness backtracing info for checking dangling witness.
    #[cfg(feature = "debug")]
    #[serde(skip)]
    pub witness_backtrace: HashMap<VarIndex, std::backtrace::Backtrace>,
}

impl<F: PrimeField> ConstraintSystem<F> for TurboCS<F> {
    fn size(&self) -> usize {
        self.size
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }

    fn n_iteration_shuffle_scalar_mul(&self) -> usize {
        self.n_iteration_shuffle_scalar_mul
    }

    fn wiring(&self) -> &[Vec<usize>] {
        &self.wiring[..]
    }

    /// `quot_eval_dom_size` divides (q-1), and should be larger than
    /// the degree of the quotient polynomial, i.e.,
    /// `quot_eval_dom_size` > 5 * `self.size` + 11.
    fn quot_eval_dom_size(&self) -> usize {
        if self.size > 8 {
            self.size * 6
        } else {
            self.size * 16
        }
    }

    fn n_wires_per_gate() -> usize {
        N_WIRES_PER_GATE
    }

    fn num_selectors() -> usize {
        N_SELECTORS
    }

    fn num_wire_selectors() -> usize {
        N_WIRE_SELECTORS
    }

    fn get_edwards_a(&self) -> F {
        self.edwards_a
    }

    fn public_vars_constraint_indices(&self) -> &[CsIndex] {
        &self.public_vars_constraint_indices
    }

    fn public_vars_witness_indices(&self) -> &[VarIndex] {
        &self.public_vars_witness_indices
    }

    fn boolean_constraint_indices(&self) -> &[CsIndex] {
        &self.boolean_constraint_indices
    }

    fn shuffle_remark_constraint_indices(&self) -> Vec<CsIndex> {
        let (indices, _): (Vec<_>, Vec<_>) = self
            .shuffle_remark_constraint_indices
            .iter()
            .cloned()
            .unzip();
        indices
    }

    fn selector(&self, index: usize) -> Result<&[F], UzkgeError> {
        if index >= self.selectors.len() {
            return Err(UzkgeError::SelectorIndexOutOfBound);
        }
        Ok(&self.selectors[index])
    }

    fn compute_witness_selectors(&self) -> [Vec<F>; N_WIRE_SELECTORS] {
        let empty_poly = vec![F::ZERO; self.size];

        let mut polys = [empty_poly.clone(), empty_poly.clone(), empty_poly];

        for (i, wire_selector) in self.shuffle_remark_constraint_indices.iter() {
            for j in 0..self.n_iteration_shuffle_scalar_mul() {
                polys[0][*i + j] = wire_selector[0][j];
                polys[1][*i + j] = wire_selector[1][j];
                polys[2][*i + j] = wire_selector[2][j];
            }
        }

        polys
    }

    /// The equation is
    /// ```text
    ///     q1*w1 + q2*w2 + q3*w3 + q4*w4 + qm1(w1*w2) + qm2(w3*w4) + qc + PI
    ///     - qo * wo = 0
    /// ```
    fn eval_gate_func(wire_vals: &[&F], sel_vals: &[&F], pub_input: &F) -> Result<F, UzkgeError> {
        if wire_vals.len() != N_WIRES_PER_GATE || sel_vals.len() != N_SELECTORS {
            return Err(UzkgeError::SelectorIndexOutOfBound);
        }
        let add1 = sel_vals[0].mul(wire_vals[0]);
        let add2 = sel_vals[1].mul(wire_vals[1]);
        let add3 = sel_vals[2].mul(wire_vals[2]);
        let add4 = sel_vals[3].mul(wire_vals[3]);
        let mul1 = sel_vals[4].mul(wire_vals[0].mul(wire_vals[1]));
        let mul2 = sel_vals[5].mul(wire_vals[2].mul(wire_vals[3]));
        let constant = sel_vals[6].add(pub_input);
        let out = sel_vals[7].mul(wire_vals[4]);
        let mut r = add1;
        r.add_assign(&add2);
        r.add_assign(&add3);
        r.add_assign(&add4);
        r.add_assign(&mul1);
        r.add_assign(&mul2);
        r.add_assign(&constant);
        r.sub_assign(&out);
        Ok(r)
    }

    /// The coefficients are
    /// (w1, w2, w3, w4, w1*w2, w3*w4, 1, -w4)
    fn eval_selector_multipliers(wire_vals: &[&F]) -> Result<Vec<F>, UzkgeError> {
        if wire_vals.len() < N_WIRES_PER_GATE {
            return Err(UzkgeError::SelectorIndexOutOfBound);
        }

        let mut w0w1w2w3w4 = *wire_vals[0];
        w0w1w2w3w4.mul_assign(wire_vals[1]);
        w0w1w2w3w4.mul_assign(wire_vals[2]);
        w0w1w2w3w4.mul_assign(wire_vals[3]);
        w0w1w2w3w4.mul_assign(wire_vals[4]);

        Ok(vec![
            *wire_vals[0],
            *wire_vals[1],
            *wire_vals[2],
            *wire_vals[3],
            wire_vals[0].mul(wire_vals[1]),
            wire_vals[2].mul(wire_vals[3]),
            F::ONE,
            wire_vals[4].neg(),
        ])
    }

    fn is_verifier_only(&self) -> bool {
        self.verifier_only
    }

    fn shrink_to_verifier_only(&self) -> Self {
        Self {
            selectors: vec![],
            wiring: [vec![], vec![], vec![], vec![], vec![]],
            edwards_a: F::ZERO,
            shuffle_public_keys_x: vec![],
            shuffle_public_keys_y: vec![],
            shuffle_public_keys_dxy: vec![],
            shuffle_generators_x: vec![],
            shuffle_generators_y: vec![],
            shuffle_generators_dxy: vec![],
            anemoi_preprocessed_round_keys_x: [[F::ZERO; 2]; N_ANEMOI_ROUNDS],
            anemoi_preprocessed_round_keys_y: [[F::ZERO; 2]; N_ANEMOI_ROUNDS],
            anemoi_generator: F::ZERO,
            anemoi_generator_inv: F::ZERO,
            anemoi_constraints_indices: vec![],
            n_iteration_shuffle_scalar_mul: self.n_iteration_shuffle_scalar_mul,
            num_vars: self.num_vars,
            size: self.size,
            public_vars_constraint_indices: vec![],
            public_vars_witness_indices: vec![],
            boolean_constraint_indices: vec![],
            shuffle_remark_constraint_indices: vec![],
            verifier_only: true,
            witness: vec![],

            #[cfg(feature = "debug")]
            witness_backtrace: HashMap::new(),
        }
    }

    fn compute_anemoi_jive_selectors(&self) -> [Vec<F>; 4] {
        let empty_poly = vec![F::ZERO; self.size];

        let mut polys = [
            empty_poly.clone(),
            empty_poly.clone(),
            empty_poly.clone(),
            empty_poly,
        ];
        for i in self.anemoi_constraints_indices.iter() {
            for j in 0..N_ANEMOI_ROUNDS {
                polys[0][*i + j] = self.anemoi_preprocessed_round_keys_x[j][0];
                polys[1][*i + j] = self.anemoi_preprocessed_round_keys_x[j][1];
                polys[2][*i + j] = self.anemoi_preprocessed_round_keys_y[j][0];
                polys[3][*i + j] = self.anemoi_preprocessed_round_keys_y[j][1];
            }
        }

        polys
    }

    fn get_anemoi_parameters(&self) -> (F, F) {
        (self.anemoi_generator, self.anemoi_generator_inv)
    }

    fn compute_shuffle_generator_selectors(&self) -> Vec<Vec<F>> {
        let mut polys = Vec::with_capacity(N_SHUFFLE_RELATED_SELECTORS / 2);
        for _ in 0..N_SHUFFLE_RELATED_SELECTORS / 2 {
            polys.push(vec![F::ZERO; self.size])
        }

        for i in self.shuffle_remark_constraint_indices().iter() {
            for j in 0..self.n_iteration_shuffle_scalar_mul() {
                polys[0][*i + j] = self.shuffle_generators_x[j][0];
                polys[1][*i + j] = self.shuffle_generators_x[j][1];
                polys[2][*i + j] = self.shuffle_generators_x[j][2];
                polys[3][*i + j] = self.shuffle_generators_x[j][3];

                polys[4][*i + j] = self.shuffle_generators_y[j][0];
                polys[5][*i + j] = self.shuffle_generators_y[j][1];
                polys[6][*i + j] = self.shuffle_generators_y[j][2];
                polys[7][*i + j] = self.shuffle_generators_y[j][3];

                polys[8][*i + j] = self.shuffle_generators_dxy[j][0];
                polys[9][*i + j] = self.shuffle_generators_dxy[j][1];
                polys[10][*i + j] = self.shuffle_generators_dxy[j][2];
                polys[11][*i + j] = self.shuffle_generators_dxy[j][3];
            }
        }

        polys
    }

    fn compute_shuffle_public_key_selectors(&self) -> Vec<Vec<F>> {
        let mut polys = Vec::with_capacity(N_SHUFFLE_RELATED_SELECTORS / 2);
        for _ in 0..N_SHUFFLE_RELATED_SELECTORS / 2 {
            polys.push(vec![F::ZERO; self.size])
        }

        for i in self.shuffle_remark_constraint_indices().iter() {
            for j in 0..self.n_iteration_shuffle_scalar_mul() {
                polys[0][*i + j] = self.shuffle_public_keys_x[j][0];
                polys[1][*i + j] = self.shuffle_public_keys_x[j][1];
                polys[2][*i + j] = self.shuffle_public_keys_x[j][2];
                polys[3][*i + j] = self.shuffle_public_keys_x[j][3];

                polys[4][*i + j] = self.shuffle_public_keys_y[j][0];
                polys[5][*i + j] = self.shuffle_public_keys_y[j][1];
                polys[6][*i + j] = self.shuffle_public_keys_y[j][2];
                polys[7][*i + j] = self.shuffle_public_keys_y[j][3];

                polys[8][*i + j] = self.shuffle_public_keys_dxy[j][0];
                polys[9][*i + j] = self.shuffle_public_keys_dxy[j][1];
                polys[10][*i + j] = self.shuffle_public_keys_dxy[j][2];
                polys[11][*i + j] = self.shuffle_public_keys_dxy[j][3];
            }
        }

        polys
    }

    fn get_hiding_degree(&self, idx: usize) -> usize {
        // The first three wires, i.e., 0, 1, 2, would require a hiding degree of 3.
        if idx < 3 {
            return 3;
        } else {
            return 2;
        }
    }
}

/// A helper function that computes the little-endian binary
/// representation of a value. Each bit is represented as a field
/// element.
fn compute_binary_le<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    let mut res = vec![];
    for byte in bytes.iter() {
        let mut tmp = *byte;
        for _ in 0..8 {
            if (tmp & 1) == 0 {
                res.push(F::ZERO);
            } else {
                res.push(F::ONE);
            }
            tmp >>= 1;
        }
    }
    res
}

impl<F: PrimeField> Default for TurboCS<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField> TurboCS<F> {
    /// Create a Plonk constraint system with a certain field size.
    /// With default witness [F::ZERO, F::ONE].
    pub fn new() -> TurboCS<F> {
        let selectors: Vec<Vec<F>> = core::iter::repeat(vec![]).take(N_SELECTORS).collect();
        let mut cs = Self {
            selectors,
            wiring: [vec![], vec![], vec![], vec![], vec![]],
            edwards_a: F::ZERO,
            shuffle_public_keys_x: vec![],
            shuffle_public_keys_y: vec![],
            shuffle_public_keys_dxy: vec![],
            shuffle_generators_x: vec![],
            shuffle_generators_y: vec![],
            shuffle_generators_dxy: vec![],
            anemoi_preprocessed_round_keys_x: [[F::ZERO; 2]; N_ANEMOI_ROUNDS],
            anemoi_preprocessed_round_keys_y: [[F::ZERO; 2]; N_ANEMOI_ROUNDS],
            anemoi_generator: F::ZERO,
            anemoi_generator_inv: F::ZERO,
            anemoi_constraints_indices: vec![],
            n_iteration_shuffle_scalar_mul: 0,
            num_vars: 2,
            size: 0,
            public_vars_constraint_indices: vec![],
            public_vars_witness_indices: vec![],
            boolean_constraint_indices: vec![],
            shuffle_remark_constraint_indices: vec![],
            verifier_only: false,
            witness: vec![F::ZERO, F::ONE],

            #[cfg(feature = "debug")]
            witness_backtrace: HashMap::new(),
        };

        cs.insert_constant_gate(cs.zero_var(), F::zero());
        cs.insert_constant_gate(cs.one_var(), F::one());

        cs
    }

    /// 0-index is Zero
    pub fn zero_var(&self) -> VarIndex {
        0
    }

    /// 1-index is One
    pub fn one_var(&self) -> VarIndex {
        1
    }

    /// Add a linear combination gate: wo = w1 * q1 + w2 * q2 + w3 * q3 + w4 * q4.
    pub fn insert_lc_gate(
        &mut self,
        wires_in: &[VarIndex; 4],
        wire_out: VarIndex,
        q1: F,
        q2: F,
        q3: F,
        q4: F,
    ) {
        assert!(
            wires_in.iter().all(|&x| x < self.num_vars),
            "input wire index out of bound"
        );
        assert!(wire_out < self.num_vars, "wire_out index out of bound");
        let zero = F::ZERO;
        self.push_add_selectors(q1, q2, q3, q4);
        self.push_mul_selectors(zero, zero);
        self.push_constant_selector(zero);
        self.push_out_selector(F::ONE);

        for (i, wire) in wires_in.iter().enumerate() {
            self.wiring[i].push(*wire);
        }
        self.wiring[4].push(wire_out);
        self.finish_new_gate();
    }

    /// Add an Add gate. (left, right, out).
    pub fn insert_add_gate(&mut self, left_var: VarIndex, right_var: VarIndex, out_var: VarIndex) {
        self.insert_lc_gate(
            &[left_var, right_var, 0, 0],
            out_var,
            F::ONE,
            F::ONE,
            F::ZERO,
            F::ZERO,
        );
    }

    /// Add a Sub gate. (left, right, out).
    pub fn insert_sub_gate(&mut self, left_var: VarIndex, right_var: VarIndex, out_var: VarIndex) {
        self.insert_lc_gate(
            &[left_var, right_var, 0, 0],
            out_var,
            F::ONE,
            F::ONE.neg(),
            F::ZERO,
            F::ZERO,
        );
    }

    /// Add a Mul gate. (left, right, out).
    pub fn insert_mul_gate(&mut self, left_var: VarIndex, right_var: VarIndex, out_var: VarIndex) {
        assert!(left_var < self.num_vars, "left_var index out of bound");
        assert!(right_var < self.num_vars, "right_var index out of bound");
        assert!(out_var < self.num_vars, "out_var index out of bound");
        let zero = F::ZERO;
        self.push_add_selectors(zero, zero, zero, zero);
        self.push_mul_selectors(F::ONE, zero);
        self.push_constant_selector(zero);
        self.push_out_selector(F::ONE);

        self.wiring[0].push(left_var);
        self.wiring[1].push(right_var);
        self.wiring[2].push(0);
        self.wiring[3].push(0);
        self.wiring[4].push(out_var);
        self.finish_new_gate();
    }

    /// Add a variable (with actual value `value`) into the constraint system.
    pub fn new_variable(&mut self, value: F) -> VarIndex {
        self.num_vars += 1;
        self.witness.push(value);

        #[cfg(feature = "debug")]
        {
            self.witness_backtrace
                .insert(self.num_vars - 1, std::backtrace::Backtrace::capture());
        }

        self.num_vars - 1
    }

    /// Add a vector of variables into the constraint system.
    pub fn add_variables(&mut self, values: &[F]) {
        self.num_vars += values.len();
        for value in values.iter() {
            self.witness.push((*value).clone());
        }

        #[cfg(feature = "debug")]
        {
            for var in self.num_vars - values.len()..self.num_vars {
                self.witness_backtrace
                    .insert(var, std::backtrace::Backtrace::capture());
            }
        }
    }

    /// Check if the gate is satisfied.
    #[cfg(feature = "debug")]
    pub fn finish_new_gate(&mut self) {
        self.size += 1;
        // does not work for the gate created for input.

        let wiring_0_var = self.wiring[0][self.size - 1];
        let wiring_1_var = self.wiring[1][self.size - 1];
        let wiring_2_var = self.wiring[2][self.size - 1];
        let wiring_3_var = self.wiring[3][self.size - 1];
        let wiring_4_var = self.wiring[4][self.size - 1];
        let wiring_0 = self.witness[wiring_0_var];
        let wiring_1 = self.witness[wiring_1_var];
        let wiring_2 = self.witness[wiring_2_var];
        let wiring_3 = self.witness[wiring_3_var];
        let wiring_4 = self.witness[wiring_4_var];

        let selector_0 = self.selectors[0][self.size - 1];
        let selector_1 = self.selectors[1][self.size - 1];
        let selector_2 = self.selectors[2][self.size - 1];
        let selector_3 = self.selectors[3][self.size - 1];
        let selector_4 = self.selectors[4][self.size - 1];
        let selector_5 = self.selectors[5][self.size - 1];
        let selector_6 = self.selectors[6][self.size - 1];
        let selector_7 = self.selectors[7][self.size - 1];
        let selector_8 = self.selectors[8][self.size - 1];

        let add1 = selector_0.mul(wiring_0);
        let add2 = selector_1.mul(wiring_1);
        let add3 = selector_2.mul(wiring_2);
        let add4 = selector_3.mul(wiring_3);
        let mul1 = selector_4.mul(wiring_0.mul(wiring_1));
        let mul2 = selector_5.mul(wiring_2.mul(wiring_3));
        let constant = selector_6;
        let out = selector_7.mul(wiring_4);
        let mut r = add1;
        r.add_assign(&add2);
        r.add_assign(&add3);
        r.add_assign(&add4);
        r.add_assign(&mul1);
        r.add_assign(&mul2);
        r.add_assign(&constant);
        r.sub_assign(&out);

        if !r.is_zero() {
            println!("{}", std::backtrace::Backtrace::capture());
            println!("cs constraint not satisfied.");
        }

        if !(selector_0.is_zero() && selector_4.is_zero()) {
            self.witness_backtrace.remove(&wiring_0_var);
        }

        if !(selector_1.is_zero() && selector_4.is_zero()) {
            self.witness_backtrace.remove(&wiring_1_var);
        }

        if !(selector_2.is_zero() && selector_5.is_zero()) {
            self.witness_backtrace.remove(&wiring_2_var);
        }

        if !(selector_3.is_zero() && selector_5.is_zero()) {
            self.witness_backtrace.remove(&wiring_3_var);
        }

        if !selector_7.is_zero() {
            self.witness_backtrace.remove(&wiring_4_var);
        }
    }

    #[cfg(not(feature = "debug"))]
    #[inline]
    /// Increase the gate count without checking.
    pub fn finish_new_gate(&mut self) {
        self.size += 1;
    }

    /// Create an output variable and insert a linear combination gate.
    pub fn linear_combine(
        &mut self,
        wires_in: &[VarIndex; 4],
        q1: F,
        q2: F,
        q3: F,
        q4: F,
    ) -> VarIndex {
        assert!(
            wires_in.iter().all(|&x| x < self.num_vars),
            "input wire index out of bound"
        );
        let w0q1 = self.witness[wires_in[0]].mul(&q1);
        let w1q2 = self.witness[wires_in[1]].mul(&q2);
        let w2q3 = self.witness[wires_in[2]].mul(&q3);
        let w3q4 = self.witness[wires_in[3]].mul(&q4);
        let mut lc = w0q1;
        lc.add_assign(&w1q2);
        lc.add_assign(&w2q3);
        lc.add_assign(&w3q4);
        let wire_out = self.new_variable(lc);
        self.insert_lc_gate(wires_in, wire_out, q1, q2, q3, q4);
        wire_out
    }

    /// Create an output variable and insert an addition gate.
    pub fn add(&mut self, left_var: VarIndex, right_var: VarIndex) -> VarIndex {
        assert!(left_var < self.num_vars, "left_var index out of bound");
        assert!(right_var < self.num_vars, "right_var index out of bound");
        let out_var = self.new_variable(self.witness[left_var].add(&self.witness[right_var]));
        self.insert_add_gate(left_var, right_var, out_var);
        out_var
    }

    /// Create an output variable and insert a subraction gate.
    pub fn sub(&mut self, left_var: VarIndex, right_var: VarIndex) -> VarIndex {
        assert!(left_var < self.num_vars, "left_var index out of bound");
        assert!(right_var < self.num_vars, "right_var index out of bound");
        let out_var = self.new_variable(self.witness[left_var].sub(&self.witness[right_var]));
        self.insert_sub_gate(left_var, right_var, out_var);
        out_var
    }

    /// Add a constraint that `left_var` and `right_var` have the same value.
    pub fn equal(&mut self, left_var: VarIndex, right_var: VarIndex) {
        let zero_var = self.zero_var();
        self.insert_sub_gate(left_var, right_var, zero_var);
    }

    /// Create an output variable and insert a multiplication gate.
    pub fn mul(&mut self, left_var: VarIndex, right_var: VarIndex) -> VarIndex {
        assert!(left_var < self.num_vars, "left_var index out of bound");
        assert!(right_var < self.num_vars, "right_var index out of bound");
        let out_var = self.new_variable(self.witness[left_var].mul(&self.witness[right_var]));
        self.insert_mul_gate(left_var, right_var, out_var);
        out_var
    }

    /// Add a Boolean constrain `var` by adding a multiplication gate:
    /// `witness[var] * witness[var] = witness[var]`
    pub fn insert_boolean_gate(&mut self, var: VarIndex) {
        self.insert_mul_gate(var, var, var);
    }

    /// Enforce a range constraint: `0 < witness[var] < 2^n_bits`:
    /// 1. Transform `witness[var]` into a binary vector and boolean
    ///    constrain the binary vector.
    /// 2. Add a set of linear combination constraints showing that
    ///    the binary vector is a binary representation of
    ///    `witness[var]`.
    /// 3. Return witness indices of the binary vector. The binary
    ///    vector is in little endian form.
    pub fn range_check(&mut self, var: VarIndex, n_bits: usize) -> Vec<VarIndex> {
        assert!(var < self.num_vars, "var index out of bound");
        assert!(n_bits >= 2, "the number of bits is less than two");
        let witness_bytes = self.witness[var].into_bigint().to_bytes_le();
        let mut binary_repr = compute_binary_le::<F>(&witness_bytes);
        while binary_repr.len() < n_bits {
            binary_repr.push(F::ZERO);
        }

        let b: Vec<VarIndex> = binary_repr
            .into_iter()
            .take(n_bits)
            .map(|val| self.new_variable(val))
            .collect();

        let one = F::ONE;
        let two = one.add(&one);
        let four = two.add(&two);
        let eight = four.add(&four);
        let bin = vec![one, two, four, eight];

        let mut acc = b[n_bits - 1];
        self.insert_boolean_gate(b[n_bits - 1]);
        let m = (n_bits - 2) / 3;
        for i in 0..m {
            acc = self.linear_combine(
                &[
                    acc,
                    b[n_bits - 1 - i * 3 - 1],
                    b[n_bits - 1 - i * 3 - 2],
                    b[n_bits - 1 - i * 3 - 3],
                ],
                bin[3],
                bin[2],
                bin[1],
                bin[0],
            );
            self.attach_boolean_constraint_to_gate();
        }
        let zero = F::ZERO;
        match (n_bits - 1) - 3 * m {
            1 => self.insert_lc_gate(&[acc, b[0], 0, 0], var, bin[1], bin[0], zero, zero),
            2 => self.insert_lc_gate(&[acc, b[1], b[0], 0], var, bin[2], bin[1], bin[0], zero),
            _ => self.insert_lc_gate(
                &[acc, b[2], b[1], b[0]],
                var,
                bin[3],
                bin[2],
                bin[1],
                bin[0],
            ),
        }
        self.attach_boolean_constraint_to_gate();
        b
    }

    /// Given two variables `var0` and `var1` and a boolean variable `bit`, return var_bit.
    /// var_bit = (1-bit) * var0 + bit * var1 = - bit * var0 + bit * var1 + var0
    /// Wires: (w1, w2, w3 , w4) = (bit, var0, bit, var1)
    /// Selectors: q2 = qm2 = qo = 1, qm1 = -1
    pub fn select(&mut self, var0: VarIndex, var1: VarIndex, bit: VarIndex) -> VarIndex {
        assert!(var0 < self.num_vars, "var0 index out of bound");
        assert!(var1 < self.num_vars, "var1 index out of bound");
        assert!(bit < self.num_vars, "bit var index out of bound");
        let zero = F::ZERO;
        let one = F::ONE;
        self.push_add_selectors(zero, one, zero, zero);
        self.push_mul_selectors(one.neg(), one);
        self.push_constant_selector(zero);
        self.push_out_selector(one);

        let out = if self.witness[bit] == zero {
            self.witness[var0].clone()
        } else {
            self.witness[var1].clone()
        };
        let out_var = self.new_variable(out);
        self.wiring[0].push(bit);
        self.wiring[1].push(var0);
        self.wiring[2].push(bit);
        self.wiring[3].push(var1);
        self.wiring[4].push(out_var);
        self.finish_new_gate();
        out_var
    }

    /// Return a boolean variable that equals 1 if and
    /// only if `left_var` == `right_var`.
    pub fn is_equal(&mut self, left_var: VarIndex, right_var: VarIndex) -> VarIndex {
        let (is_equal, _) = self.is_equal_or_not_equal(left_var, right_var);
        is_equal
    }

    /// Return a boolean variable that equals 1 if and
    /// only if `left_var` != `right_var`.
    pub fn is_not_equal(&mut self, left_var: VarIndex, right_var: VarIndex) -> VarIndex {
        let (_, is_not_equal) = self.is_equal_or_not_equal(left_var, right_var);
        is_not_equal
    }

    /// Return two boolean variables that equals (1, 0) if and
    /// only if `left_var` == `right_var` and (0, 1) otherwise.
    pub fn is_equal_or_not_equal(
        &mut self,
        left_var: VarIndex,
        right_var: VarIndex,
    ) -> (VarIndex, VarIndex) {
        let diff = self.sub(left_var, right_var);
        // set `inv_diff` = `diff`^{-1} when `diff` != 0, otherwise we can set `inv_diff` to arbirary value since `diff` * `inv_diff` will always be 0 when `diff` == 0
        let inv_diff_scalar = self.witness[diff].inverse().unwrap_or(F::ZERO);
        let inv_diff = self.new_variable(inv_diff_scalar);

        // `diff_is_zero` = 1 - `diff` * `inv_diff`
        // `diff_is_zero` will be 1 when `diff` == 0, and `diff_is_zero` will be 0 when `diff != 0` and `inv_diff` == `diff`^{-1}
        let mul_var = self.mul(diff, inv_diff);
        let one_var = self.one_var();
        let diff_is_zero = self.sub(one_var, mul_var);

        // enforce `diff` * `diff_is_zero` == 0
        // without this constraint, a malicious prover can set `diff_is_zero` to arbitrary value when `diff` != 0
        let zero_var = self.zero_var();
        self.insert_mul_gate(diff, diff_is_zero, zero_var);

        (diff_is_zero, mul_var)
    }

    /// Add a constant constraint: wo = constant.
    pub fn insert_constant_gate(&mut self, var: VarIndex, constant: F) {
        assert!(var < self.num_vars, "variable index out of bound");
        let zero = F::ZERO;
        self.push_add_selectors(zero, zero, zero, zero);
        self.push_mul_selectors(zero, zero);
        self.push_constant_selector(constant);
        self.push_out_selector(F::ONE);

        for i in 0..N_WIRES_PER_GATE {
            self.wiring[i].push(var);
        }

        // The constant should be used somewhere else so it should be removed by another gate.
        //
        // Therefore, here we save the backtrace information,  so that `finish_new_gate` does not
        // delete such information, and then put it back to the list of witness backtrace.
        #[cfg(feature = "debug")]
        let backtrace = { self.witness_backtrace.remove(&var) };

        self.finish_new_gate();

        #[cfg(feature = "debug")]
        {
            match backtrace {
                Some(v) => self.witness_backtrace.insert(var, v),
                None => None,
            };
        }
    }

    /// Add a constant constraint: wo = constant, for prepare_pi_variable.
    pub fn insert_constant_gate_for_input(&mut self, var: VarIndex, constant: F) {
        assert!(var < self.num_vars, "variable index out of bound");
        let zero = F::ZERO;
        self.push_add_selectors(zero, zero, zero, zero);
        self.push_mul_selectors(zero, zero);
        self.push_constant_selector(constant);
        self.push_out_selector(F::ONE);

        for i in 0..N_WIRES_PER_GATE {
            self.wiring[i].push(var);
        }
        self.size += 1;
    }

    /// Add constraint of a public IO value to be decided online.
    pub fn prepare_pi_variable(&mut self, var: VarIndex) {
        self.public_vars_witness_indices.push(var);
        self.public_vars_constraint_indices.push(self.size);
        self.insert_constant_gate_for_input(var, F::ZERO);
    }

    /// Add constraint that certain values must be one or zero.
    pub fn attach_boolean_constraint_to_gate(&mut self) {
        self.boolean_constraint_indices.push(self.size - 1);
    }

    /// Add constraints about the Anemoi/Jive hash function.
    pub fn attach_anemoi_jive_constraints_to_gate(&mut self) {
        debug_assert!(!self.anemoi_generator.is_zero());
        self.anemoi_constraints_indices.push(self.size - 1);
    }

    /// Add constraints about the shuffle remark.
    pub fn attach_shuffle_remark_constraints_to_gate(
        &mut self,
        wiring_selectors: [Vec<F>; N_WIRE_SELECTORS],
    ) {
        for x in wiring_selectors.iter() {
            assert_eq!(x.len(), self.n_iteration_shuffle_scalar_mul);
        }
        self.shuffle_remark_constraint_indices
            .push((self.size, wiring_selectors));
    }

    /// Set the parameters for the Anemoi/Jive hash function.
    pub fn load_anemoi_parameters<H: AnemoiJive<F, 2, N_ANEMOI_ROUNDS>>(&mut self) {
        self.anemoi_preprocessed_round_keys_x = H::PREPROCESSED_ROUND_KEYS_X;
        self.anemoi_preprocessed_round_keys_y = H::PREPROCESSED_ROUND_KEYS_Y;

        self.anemoi_generator = H::GENERATOR;
        self.anemoi_generator_inv = H::GENERATOR_INV;
    }

    /// Set the parameters for the shuffle remark.
    pub fn load_shuffle_remark_parameters<G: CurveGroup<BaseField = F>, H: Remark<G>>(
        &mut self,
        shuffle_pk: &G,
    ) {
        let generators_x = H::get_preprocessed_generators_x();
        let generators_y = H::get_preprocessed_generators_y();
        let generators_dxy = H::get_preprocessed_generators_dxy();

        let public_keys = H::crate_public_keys(shuffle_pk);

        let mut public_keys_x = vec![];
        let mut public_keys_y = vec![];
        let mut public_keys_dxy = vec![];

        for i in public_keys.iter() {
            let mut pk_x_tmp = vec![];
            let mut pk_y_tmp = vec![];
            let mut pk_dxy_tmp = vec![];
            for j in i.iter() {
                let (x, y) = j.into_affine().xy().unwrap();
                let dxy = x.mul(y).mul(H::COFF_D);
                pk_x_tmp.push(x);
                pk_y_tmp.push(y);
                pk_dxy_tmp.push(dxy);
            }

            public_keys_x.push(pk_x_tmp);
            public_keys_y.push(pk_y_tmp);
            public_keys_dxy.push(pk_dxy_tmp);
        }

        self.edwards_a = H::COFF_A;
        self.n_iteration_shuffle_scalar_mul = H::NUM_ITERATIONS;
        self.shuffle_public_keys_x = public_keys_x;
        self.shuffle_public_keys_y = public_keys_y;
        self.shuffle_public_keys_dxy = public_keys_dxy;
        self.shuffle_generators_x = generators_x;
        self.shuffle_generators_y = generators_y;
        self.shuffle_generators_dxy = generators_dxy;
    }

    /// Pad the number of constraints to a power of two.
    pub fn pad(&mut self) {
        let n = self.size.next_power_of_two();
        let diff = n - self.size();
        for selector in self.selectors.iter_mut() {
            selector.extend(vec![F::ZERO; diff]);
        }
        for wire in self.wiring.iter_mut() {
            wire.extend(vec![0; diff]);
        }
        self.size += diff;

        #[cfg(feature = "debug")]
        {
            if !self.witness_backtrace.is_empty() {
                let mut animoi_witness_var = Vec::new();
                for cs_index in self.anemoi_constraints_indices.iter() {
                    for r in 0..N_ANEMOI_ROUNDS {
                        animoi_witness_var.push(self.get_witness_index(0, cs_index + r));
                        animoi_witness_var.push(self.get_witness_index(1, cs_index + r));
                        animoi_witness_var.push(self.get_witness_index(2, cs_index + r));
                        animoi_witness_var.push(self.get_witness_index(3, cs_index + r));
                        animoi_witness_var.push(self.get_witness_index(4, cs_index + r));
                    }
                }

                for (var, backtrace) in &self.witness_backtrace {
                    if animoi_witness_var.contains(var) {
                        continue;
                    }

                    panic!("dangling witness:\n{}", backtrace);
                }
            }
        }
    }

    /// Add a Add selectors.
    pub fn push_add_selectors(&mut self, q1: F, q2: F, q3: F, q4: F) {
        self.selectors[0].push(q1);
        self.selectors[1].push(q2);
        self.selectors[2].push(q3);
        self.selectors[3].push(q4);
    }

    /// Add a Mul selectors.
    pub fn push_mul_selectors(&mut self, q_mul12: F, q_mul34: F) {
        self.selectors[4].push(q_mul12);
        self.selectors[5].push(q_mul34);
    }

    /// Add a constant selectors.
    pub fn push_constant_selector(&mut self, q_c: F) {
        self.selectors[6].push(q_c);
    }

    /// Add an Out selectors.
    pub fn push_out_selector(&mut self, q_out: F) {
        self.selectors[7].push(q_out);
    }

    /// Return the witness index for given wire and cs index.
    fn get_witness_index(&self, wire_index: usize, cs_index: CsIndex) -> VarIndex {
        assert!(wire_index < N_WIRES_PER_GATE, "wire index out of bound");
        assert!(cs_index < self.size, "constraint index out of bound");
        self.wiring[wire_index][cs_index]
    }

    /// Verify the given witness and publics.
    pub fn verify_witness(&self, witness: &[F], online_vars: &[F]) -> Result<(), UzkgeError> {
        if witness.len() != self.num_vars {
            return Err(UzkgeError::Message(format!(
                "witness len = {}, num_vars = {}",
                witness.len(),
                self.num_vars
            )));
        }
        if online_vars.len() != self.public_vars_witness_indices.len()
            || online_vars.len() != self.public_vars_constraint_indices.len()
        {
            return Err(UzkgeError::Message(
                "wrong number of online variables".to_owned(),
            ));
        }

        if !self.anemoi_constraints_indices.is_empty() {
            assert!(!self.anemoi_generator.is_zero());
        }

        for cs_index in self.anemoi_constraints_indices.iter() {
            for r in 0..N_ANEMOI_ROUNDS {
                let a_i = witness[self.get_witness_index(0, cs_index + r)].clone();
                let b_i = witness[self.get_witness_index(1, cs_index + r)].clone();
                let c_i = witness[self.get_witness_index(2, cs_index + r)].clone();
                let d_i = witness[self.get_witness_index(3, cs_index + r)].clone();
                let o_i = witness[self.get_witness_index(4, cs_index + r)].clone();

                let a_i_next = witness[self.get_witness_index(0, cs_index + 1 + r)].clone();
                let b_i_next = witness[self.get_witness_index(1, cs_index + 1 + r)].clone();
                let c_i_next = witness[self.get_witness_index(2, cs_index + 1 + r)].clone();
                let d_i_next = witness[self.get_witness_index(3, cs_index + 1 + r)].clone();

                if o_i != d_i_next {
                    return Err(UzkgeError::Message(format!(
                        "cs index {} round {}: the output wire {:?} does not equal to the fourth wire {:?} in the next constraint",
                        cs_index,
                        r,
                        o_i,
                        d_i_next
                    )));
                }

                let prk_i_a = self.anemoi_preprocessed_round_keys_x[r][0].clone();
                let prk_i_b = self.anemoi_preprocessed_round_keys_x[r][1].clone();
                let prk_i_c = self.anemoi_preprocessed_round_keys_y[r][0].clone();
                let prk_i_d = self.anemoi_preprocessed_round_keys_y[r][1].clone();

                let g = self.anemoi_generator.clone();
                let g2 = g.square().add(F::ONE);

                let da_i = a_i + d_i;
                let cb_i = b_i + c_i;

                let d2a_i = da_i + a_i;
                let c2b_i = cb_i + b_i;

                // equation 1
                let left = (da_i + g * cb_i + prk_i_c - &c_i_next).pow(&[5u64])
                    + g * (da_i + g * cb_i + prk_i_c).square();
                let right = d2a_i + g * c2b_i + prk_i_a;
                if left != right {
                    return Err(UzkgeError::Message(format!(
                        "cs index {} round {}: the first of anemoi equation does not equal: {:?} != {:?}",
                        cs_index, r, left, right
                    )));
                }

                // equation 2
                let left = (g * da_i + g2 * cb_i + prk_i_d - &d_i_next).pow(&[5u64])
                    + g * (g * da_i + g2 * cb_i + prk_i_d).square();
                let right = g * d2a_i + g2 * c2b_i + prk_i_b;
                if left != right {
                    return Err(UzkgeError::Message(format!(
                        "cs index {} round {}: the second equation of anemoi does not equal: {:?} != {:?}",
                        cs_index, r, left, right
                    )));
                }

                // equation 3
                let left = (da_i + g * cb_i + prk_i_c - &c_i_next).pow(&[5u64])
                    + g * c_i_next.square()
                    + &self.anemoi_generator_inv;
                let right = a_i_next;
                if left != right {
                    return Err(UzkgeError::Message(format!(
                        "cs index {} round {}: the third equation of anemoi does not equal: {:?} != {:?}",
                        cs_index, r, left, right
                    )));
                }

                // equation 4
                let left = (g * da_i + g2 * cb_i + prk_i_d - &d_i_next).pow(&[5u64])
                    + g * d_i_next.square()
                    + &self.anemoi_generator_inv;
                let right = b_i_next;
                if left != right {
                    return Err(UzkgeError::Message(format!(
                        "cs index {} round {}: the fourth equation of anemoi does not equal: {:?} != {:?}",
                        cs_index, r, left, right
                    )));
                }
            }
        }

        let one = F::one();
        let zero = F::zero();
        let minus_one = -one;

        if !self.shuffle_remark_constraint_indices.is_empty() {
            assert!(!self.edwards_a.is_zero());
        }

        for (cs_index, wiring_selectors) in self.shuffle_remark_constraint_indices.iter() {
            for r in 0..self.n_iteration_shuffle_scalar_mul {
                let a_i = witness[self.get_witness_index(0, cs_index + r)].clone();
                let b_i = witness[self.get_witness_index(1, cs_index + r)].clone();
                let c_i = witness[self.get_witness_index(2, cs_index + r)].clone();
                let d_i = witness[self.get_witness_index(3, cs_index + r)].clone();
                let o_i = witness[self.get_witness_index(4, cs_index + r)].clone();

                let a_i_next = witness[self.get_witness_index(0, cs_index + 1 + r)].clone();
                let b_i_next = witness[self.get_witness_index(1, cs_index + 1 + r)].clone();
                let c_i_next = witness[self.get_witness_index(2, cs_index + 1 + r)].clone();
                let d_i_next = witness[self.get_witness_index(3, cs_index + 1 + r)].clone();
                assert_eq!(o_i, d_i_next);

                let s1_i = wiring_selectors[0][r];
                let s2_i = wiring_selectors[1][r];
                let s3_i = wiring_selectors[2][r];

                // check special binary testing
                if !s1_i.is_zero() && !s1_i.is_one() {
                    return Err(UzkgeError::Message(format!(
                        "cs index {}: the first wire selector {:?} is not one or zero",
                        cs_index, s1_i
                    )));
                }

                if !s2_i.is_zero() && !s2_i.is_one() {
                    return Err(UzkgeError::Message(format!(
                        "cs index {}: the second wire selector {:?} is not one or zero",
                        cs_index, s2_i
                    )));
                }

                if s3_i != minus_one && !s3_i.is_one() {
                    return Err(UzkgeError::Message(format!(
                        "cs index {}: the third wire selector {:?} is not one or minus one",
                        cs_index, s3_i
                    )));
                }

                let pk_x_0_0 = self.shuffle_public_keys_x[r][0].clone();
                let pk_x_0_1 = self.shuffle_public_keys_x[r][1].clone();
                let pk_x_1_0 = self.shuffle_public_keys_x[r][2].clone();
                let pk_x_1_1 = self.shuffle_public_keys_x[r][3].clone();

                let pk_y_0_0 = self.shuffle_public_keys_y[r][0].clone();
                let pk_y_0_1 = self.shuffle_public_keys_y[r][1].clone();
                let pk_y_1_0 = self.shuffle_public_keys_y[r][2].clone();
                let pk_y_1_1 = self.shuffle_public_keys_y[r][3].clone();

                let pk_dxy_0_0 = self.shuffle_public_keys_dxy[r][0].clone();
                let pk_dxy_0_1 = self.shuffle_public_keys_dxy[r][1].clone();
                let pk_dxy_1_0 = self.shuffle_public_keys_dxy[r][2].clone();
                let pk_dxy_1_1 = self.shuffle_public_keys_dxy[r][3].clone();

                let g_x_0_0 = self.shuffle_generators_x[r][0].clone();
                let g_x_0_1 = self.shuffle_generators_x[r][1].clone();
                let g_x_1_0 = self.shuffle_generators_x[r][2].clone();
                let g_x_1_1 = self.shuffle_generators_x[r][3].clone();

                let g_y_0_0 = self.shuffle_generators_y[r][0].clone();
                let g_y_0_1 = self.shuffle_generators_y[r][1].clone();
                let g_y_1_0 = self.shuffle_generators_y[r][2].clone();
                let g_y_1_1 = self.shuffle_generators_y[r][3].clone();

                let g_dxy_0_0 = self.shuffle_generators_dxy[r][0].clone();
                let g_dxy_0_1 = self.shuffle_generators_dxy[r][1].clone();
                let g_dxy_1_0 = self.shuffle_generators_dxy[r][2].clone();
                let g_dxy_1_1 = self.shuffle_generators_dxy[r][3].clone();

                // equation 1
                let result = (one - s1_i)
                    * (one - s2_i)
                    * (s3_i * a_i_next - s3_i * a_i * pk_y_0_0 - b_i * pk_x_0_0
                        + a_i * b_i * a_i_next * pk_dxy_0_0)
                    + s1_i
                        * (one - s2_i)
                        * (s3_i * a_i_next - s3_i * a_i * pk_y_0_1 - b_i * pk_x_0_1
                            + a_i * b_i * a_i_next * pk_dxy_0_1)
                    + (one - s1_i)
                        * s2_i
                        * (s3_i * a_i_next - s3_i * a_i * pk_y_1_0 - b_i * pk_x_1_0
                            + a_i * b_i * a_i_next * pk_dxy_1_0)
                    + s1_i
                        * s2_i
                        * (s3_i * a_i_next - s3_i * a_i * pk_y_1_1 - b_i * pk_x_1_1
                            + a_i * b_i * a_i_next * pk_dxy_1_1);
                if !result.is_zero() {
                    return Err(UzkgeError::Message(format!(
                        "cs index {} round {}: the first equation of shuffle does not equal: {:?} != {:?}",
                        cs_index, r, result, zero
                    )));
                }

                // equation 2
                let result = (one - s1_i)
                    * (one - s2_i)
                    * (s3_i * b_i_next + self.edwards_a * a_i * pk_x_0_0
                        - s3_i * b_i * pk_y_0_0
                        - a_i * b_i * b_i_next * pk_dxy_0_0)
                    + s1_i
                        * (one - s2_i)
                        * (s3_i * b_i_next + self.edwards_a * a_i * pk_x_0_1
                            - s3_i * b_i * pk_y_0_1
                            - a_i * b_i * b_i_next * pk_dxy_0_1)
                    + (one - s1_i)
                        * s2_i
                        * (s3_i * b_i_next + self.edwards_a * a_i * pk_x_1_0
                            - s3_i * b_i * pk_y_1_0
                            - a_i * b_i * b_i_next * pk_dxy_1_0)
                    + s1_i
                        * s2_i
                        * (s3_i * b_i_next + self.edwards_a * a_i * pk_x_1_1
                            - s3_i * b_i * pk_y_1_1
                            - a_i * b_i * b_i_next * pk_dxy_1_1);
                if !result.is_zero() {
                    return Err(UzkgeError::Message(format!(
                                 "cs index {} round {}: the second equation of shuffle does not equal: {:?} != {:?}",
                                 cs_index, r, result, zero
                             )));
                }

                // equation 3
                let result = (one - s1_i)
                    * (one - s2_i)
                    * (s3_i * c_i_next - s3_i * c_i * g_y_0_0 - d_i * g_x_0_0
                        + c_i * d_i * c_i_next * g_dxy_0_0)
                    + s1_i
                        * (one - s2_i)
                        * (s3_i * c_i_next - s3_i * c_i * g_y_0_1 - d_i * g_x_0_1
                            + c_i * d_i * c_i_next * g_dxy_0_1)
                    + (one - s1_i)
                        * s2_i
                        * (s3_i * c_i_next - s3_i * c_i * g_y_1_0 - d_i * g_x_1_0
                            + c_i * d_i * c_i_next * g_dxy_1_0)
                    + s1_i
                        * s2_i
                        * (s3_i * c_i_next - s3_i * c_i * g_y_1_1 - d_i * g_x_1_1
                            + c_i * d_i * c_i_next * g_dxy_1_1);
                if !result.is_zero() {
                    return Err(UzkgeError::Message(format!(
                                           "cs index {} round {}: the third equation of shuffle does not equal: {:?} != {:?}",
                                           cs_index, r, result, zero
                                       )));
                }

                // equation 4
                let result = (one - s1_i)
                    * (one - s2_i)
                    * (s3_i * o_i + self.edwards_a * c_i * g_x_0_0
                        - s3_i * d_i * g_y_0_0
                        - c_i * d_i * o_i * g_dxy_0_0)
                    + s1_i
                        * (one - s2_i)
                        * (s3_i * o_i + self.edwards_a * c_i * g_x_0_1
                            - s3_i * d_i * g_y_0_1
                            - c_i * d_i * o_i * g_dxy_0_1)
                    + (one - s1_i)
                        * s2_i
                        * (s3_i * o_i + self.edwards_a * c_i * g_x_1_0
                            - s3_i * d_i * g_y_1_0
                            - c_i * d_i * o_i * g_dxy_1_0)
                    + s1_i
                        * s2_i
                        * (s3_i * o_i + self.edwards_a * c_i * g_x_1_1
                            - s3_i * d_i * g_y_1_1
                            - c_i * d_i * o_i * g_dxy_1_1);
                if !result.is_zero() {
                    return Err(UzkgeError::Message(format!(
                                                       "cs index {} round {}: the fourth equation of shuffle does not equal: {:?} != {:?}",
                                                       cs_index, r, result, zero
                                                   )));
                }
            }
        }

        for cs_index in 0..self.size() {
            let mut public_online = F::ZERO;
            // check if the constraint constrains a public variable
            // search constraint index in online vars
            for ((c_i, w_i), online_var) in self
                .public_vars_constraint_indices
                .iter()
                .zip(self.public_vars_witness_indices.iter())
                .zip(online_vars.iter())
            {
                if *c_i == cs_index {
                    // found
                    public_online = (*online_var).clone();
                    if witness[*w_i] != public_online {
                        return Err(UzkgeError::Message(format!(
                            "cs index {}: online var {:?} does not match witness {:?}",
                            cs_index,
                            public_online,
                            witness[*w_i].clone()
                        )));
                    }
                }
            }
            let w1_value = &witness[self.get_witness_index(0, cs_index)];
            let w2_value = &witness[self.get_witness_index(1, cs_index)];
            let w3_value = &witness[self.get_witness_index(2, cs_index)];
            let w4_value = &witness[self.get_witness_index(3, cs_index)];
            let w_out_value = &witness[self.get_witness_index(4, cs_index)];
            let wire_vals = vec![w1_value, w2_value, w3_value, w4_value, w_out_value];
            let sel_vals: Vec<&F> = (0..Self::num_selectors())
                .map(|i| &self.selectors[i][cs_index])
                .collect();
            let eval_gate = Self::eval_gate_func(&wire_vals, &sel_vals, &public_online)?;

            if eval_gate != F::ZERO {
                return Err(UzkgeError::Message(format!(
                    "cs index {}: wire_vals = ({:?}), sel_vals = ({:?})",
                    cs_index, wire_vals, sel_vals
                )));
            }

            if self.boolean_constraint_indices.contains(&cs_index) {
                if !w2_value.is_zero() && !w2_value.is_one() {
                    return Err(UzkgeError::Message(format!(
                        "cs index {}: the second wire {:?} is not one or zero",
                        cs_index, w2_value
                    )));
                }

                if !w3_value.is_zero() && !w3_value.is_one() {
                    return Err(UzkgeError::Message(format!(
                        "cs index {}: the third wire {:?} is not one or zero",
                        cs_index, w3_value
                    )));
                }

                if !w4_value.is_zero() && !w4_value.is_one() {
                    return Err(UzkgeError::Message(format!(
                        "cs index {}: the fourth wire {:?} is not one or zero",
                        cs_index, w4_value
                    )));
                }
            }
        }
        Ok(())
    }

    /// Extract and clear the entire witness of the circuit. The witness consists of
    /// secret inputs, public inputs, and the values of intermediate variables.
    pub fn get_and_clear_witness(&mut self) -> Vec<F> {
        let res = self.witness.clone();
        self.witness.clear();
        res
    }
}
