mod babyjubjub;
mod permutation;
mod remark;
mod trace;

pub use babyjubjub::BabyJubjubShuffle;
pub use permutation::Permutation;
pub use remark::Remark;
pub use trace::RemarkTrace;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::{CryptoRng, RngCore};

pub const N_SELECT_BITS: usize = 4;

/// An ElGamal ciphertext
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct Ciphertext<C: CurveGroup> {
    /// `e1` = `r * G`
    pub e1: C,
    /// `e2` = `M + r * pk`
    pub e2: C,
}

impl<C: CurveGroup> Ciphertext<C> {
    pub fn new(e1: C, e2: C) -> Self {
        Self { e1, e2 }
    }

    pub fn rand<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let m = C::rand(prng);
        let pk = C::rand(prng);
        Self::encrypt(prng, &m, &pk)
    }

    pub fn encrypt<R: CryptoRng + RngCore>(prng: &mut R, m: &C, pk: &C) -> Self {
        let g = C::generator();

        let r = C::ScalarField::rand(prng);
        let e1 = g.mul(&r);
        let e2 = m.add(pk.mul(r));

        Self::new(e1, e2)
    }

    pub fn verify(&self, m: &C, sk: &C::ScalarField) -> bool {
        *m == self.get_second().sub(self.get_first().mul(sk))
    }

    pub fn get_first(&self) -> C {
        self.e1
    }

    pub fn get_second(&self) -> C {
        self.e2
    }

    pub fn flatten(&self) -> [C::BaseField; 4] {
        let (x1, y1) = self.e1.into_affine().xy().unwrap();
        let (x2, y2) = self.e2.into_affine().xy().unwrap();
        [x2, y2, x1, y1]
    }
}
