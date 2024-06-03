/// Module for ECC where the base is a constant to the circuit.
pub mod const_base_ecc;

/// Module for ECC where the base is not a constant.
pub mod nonconst_base_ecc;

use ark_ec::twisted_edwards::{Affine, Projective, TECurveConfig};
use ark_ff::PrimeField;

use crate::plonk::constraint_system::{TurboCS, VarIndex};

#[derive(Default, Clone, Copy)]
/// The witness indices for x/y-coordinates of a point
pub struct PointVar(VarIndex, VarIndex);

/// PointVar plus the corresponding  point
pub struct ExtendedPointVar<T: TECurveConfig>(PointVar, Projective<T>);

impl<T: TECurveConfig> ExtendedPointVar<T> {
    /// Return the point variable.
    pub fn get_var(&self) -> &PointVar {
        &self.0
    }

    /// Return the point value.
    pub fn get_point(&self) -> &Projective<T> {
        &self.1
    }

    /// Return the point variable
    pub fn into_point_var(self) -> PointVar {
        self.0
    }
}

impl PointVar {
    /// Crate a point variable.
    pub fn new(x_var: VarIndex, y_var: VarIndex) -> PointVar {
        PointVar(x_var, y_var)
    }

    /// Return x-coordinate of the point variable.
    pub fn get_x(&self) -> VarIndex {
        self.0
    }

    /// Return y-coordinate of the point variable.
    pub fn get_y(&self) -> VarIndex {
        self.1
    }
}

impl<F: PrimeField> TurboCS<F> {
    /// Create variables for a point.
    pub fn new_point_variable<T: TECurveConfig<BaseField = F>>(
        &mut self,
        point: Projective<T>,
    ) -> PointVar {
        let affine: Affine<T> = point.into();

        let x = self.new_variable(affine.x);
        let y = self.new_variable(affine.y);
        PointVar(x, y)
    }

    /// Insert constraint for a public IO point to be decided online.
    pub fn prepare_pi_point_variable(&mut self, point_var: PointVar) {
        self.prepare_pi_variable(point_var.0);
        self.prepare_pi_variable(point_var.1);
    }

    /// Insert a curve addition gate: (x1, y1) + (x2, y2) = (x3, y3)
    ///
    /// x-coordinate constraint:
    /// x3 = x1 * y2 + y1 * x2 - d * x1 * y1 * x2 * y2 * x3
    /// wirings: w1 = x1, w2 = y2, w3 = x2, w4 = y1, w_out = x3
    /// selectors: qm1 = 1, qm2 = 1, q_ecc = -d, qo = 1
    ///
    /// y-coordinate constraint:
    /// y3 = -a * x1 * x2 + y1 * y2 + d * x1 * y1 * x2 * y2 * y3
    /// wirings: w1 = x1, w2 = x2, w3 = y1, w4 = y2, w_out = y3
    /// selectors: qm1 = -a, qm2 = 1, q_ecc = d, qo = 1
    fn insert_ecc_add_gate<T: TECurveConfig<BaseField = F>>(
        &mut self,
        p1_var: &PointVar,
        p2_var: &PointVar,
        p_out_var: &PointVar,
    ) {
        assert!(p1_var.0 < self.num_vars, "p1.x variable index out of bound");
        assert!(p1_var.1 < self.num_vars, "p1.y variable index out of bound");
        assert!(p2_var.0 < self.num_vars, "p2.x variable index out of bound");
        assert!(p2_var.1 < self.num_vars, "p2.y variable index out of bound");
        assert!(
            p_out_var.0 < self.num_vars,
            "p_out.x variable index out of bound"
        );
        assert!(
            p_out_var.1 < self.num_vars,
            "p_out.y variable index out of bound"
        );

        // x-coordinate constraint
        let zero = F::zero();
        let one = F::one();
        self.push_add_selectors(zero, zero, zero, zero);
        self.push_mul_selectors(one, one);
        self.push_constant_selector(zero);
        self.push_ecc_selector(-T::COEFF_D);
        self.push_out_selector(one);

        self.wiring[0].push(p1_var.0);
        self.wiring[1].push(p2_var.1);
        self.wiring[2].push(p2_var.0);
        self.wiring[3].push(p1_var.1);
        self.wiring[4].push(p_out_var.0);
        self.size += 1;

        // y-coordinate constraint
        self.push_add_selectors(zero, zero, zero, zero);
        self.push_mul_selectors(-T::COEFF_A, one);
        self.push_constant_selector(zero);
        self.push_ecc_selector(T::COEFF_D);
        self.push_out_selector(one);

        self.wiring[0].push(p1_var.0);
        self.wiring[1].push(p2_var.0);
        self.wiring[2].push(p1_var.1);
        self.wiring[3].push(p2_var.1);
        self.wiring[4].push(p_out_var.1);
        self.finish_new_gate();
    }

    /// Given two elliptic curve point variables `[P1]` and `[P2]`, returns `[P1] + [P2]`
    pub fn ecc_add<T: TECurveConfig<BaseField = F>>(
        &mut self,
        p1_var: &PointVar,
        p2_var: &PointVar,
        p1_ext: &Projective<T>,
        p2_ext: &Projective<T>,
    ) -> ExtendedPointVar<T> {
        assert!(p1_var.0 < self.num_vars, "p1.x variable index out of bound");
        assert!(p1_var.1 < self.num_vars, "p1.y variable index out of bound");
        assert!(p2_var.0 < self.num_vars, "p2.x variable index out of bound");
        assert!(p2_var.1 < self.num_vars, "p2.y variable index out of bound");
        let p_out_ext = p1_ext + p2_ext;
        let p_out_var = self.new_point_variable(p_out_ext);
        self.insert_ecc_add_gate::<T>(p1_var, p2_var, &p_out_var);
        ExtendedPointVar(p_out_var, p_out_ext)
    }
}
