pub mod permutation;
pub mod remark;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::ops::Index;

use crate::{
    shuffle::{Ciphertext, N_SELECT_BITS},
    plonk::constraint_system::{TurboCS, VarIndex},
};

#[derive(Debug, Clone, Default)]
pub struct CardVar([VarIndex; N_SELECT_BITS]);

impl CardVar {
    pub fn new(vars: &[VarIndex; 4]) -> Self {
        Self(vars.clone())
    }

    pub fn get_raw(&self) -> [VarIndex; N_SELECT_BITS] {
        self.0
    }

    pub fn get_first_x(&self) -> VarIndex {
        self.0[0]
    }

    pub fn get_first_y(&self) -> VarIndex {
        self.0[1]
    }

    pub fn get_second_x(&self) -> VarIndex {
        self.0[2]
    }

    pub fn get_second_y(&self) -> VarIndex {
        self.0[3]
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn set(&mut self, index: usize, value: VarIndex) {
        self.0[index] = value
    }
}

impl Index<usize> for CardVar {
    type Output = VarIndex;

    fn index(&self, index: usize) -> &VarIndex {
        match index {
            0 => &self.0[0],
            1 => &self.0[1],
            2 => &self.0[2],
            3 => &self.0[3],
            _ => panic!("Index out of bounds"),
        }
    }
}

impl<F: PrimeField> TurboCS<F> {
    pub fn new_card_variable<C: CurveGroup<BaseField = F>>(
        &mut self,
        card: &Ciphertext<C>,
    ) -> CardVar {
        let (first_x, first_y) = card.get_first().into_affine().xy().unwrap();
        let (second_x, second_y) = card.get_second().into_affine().xy().unwrap();

        let first_x_var = self.new_variable(first_x);
        let first_y_var = self.new_variable(first_y);
        let second_x_var = self.new_variable(second_x);
        let second_y_var = self.new_variable(second_y);

        CardVar::new(&[second_x_var, second_y_var, first_x_var, first_y_var])
    }

    pub fn prepare_pi_card_variable(&mut self, card_var: &CardVar) {
        for var in card_var.get_raw().iter() {
            self.prepare_pi_variable(*var);
        }
    }
}
