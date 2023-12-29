use ark_ff::PrimeField;
use ark_std::rand::Rng;
use rand_chacha::rand_core::{CryptoRng, RngCore};

#[derive(Debug)]
pub struct Permutation<F: PrimeField>(Vec<Vec<F>>);

impl<F: PrimeField> Permutation<F> {
    pub fn rand<R: CryptoRng + RngCore>(prng: &mut R, n: usize) -> Self {
        let mut permutation_matrix = vec![vec![F::ZERO; n]; n];

        let mut remainder = (0..n).collect::<Vec<usize>>();

        for i in 0..n {
            let r = prng.gen_range(0..remainder.len());
            let index = remainder[r];
            remainder.remove(r);

            permutation_matrix[i][index] = F::ONE;
        }

        Permutation(permutation_matrix)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get_matrix(&self) -> &Vec<Vec<F>> {
        &self.0
    }

    pub fn sanity_check(&self) {
        for matrixs in self.get_matrix().iter() {
            assert_eq!(F::ONE, matrixs.iter().sum())
        }

        (0..self.0.len()).for_each(|j| {
            let x = (0..self.0[j].len()).map(|i| self.get_matrix()[i][j]).sum();
            assert_eq!(F::ONE, x)
        })
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::Fr;
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};

    use super::Permutation;

    #[test]
    fn test_permutation() {
        let mut prng = ChaChaRng::from_entropy();
        Permutation::<Fr>::rand(&mut prng, 52).sanity_check();
    }
}
