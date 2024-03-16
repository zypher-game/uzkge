use ark_ff::PrimeField;

/// The MDS matrix
pub struct MDSMatrix<F: PrimeField, const N: usize>(pub [[F; N]; N]);

impl<F: PrimeField, const N: usize> Default for MDSMatrix<F, N> {
    fn default() -> Self {
        Self([[F::default(); N]; N])
    }
}

/// The trait for MDS matrix that can be used in Anemoi-Jive CRH.
pub trait ApplicableMDSMatrix<F: PrimeField, const N: usize> {
    /// Construct the MDS matrix from the generator.
    fn from_generator(generator: &F) -> Self;

    /// Perform the permutation in place.
    fn permute_in_place(&self, x: &mut [F; N], y: &mut [F; N]);

    /// Perform the permutation and return the result.
    fn permute(&self, x: &[F; N], y: &[F; N]) -> ([F; N], [F; N]) {
        let mut x: [F; N] = x.clone();
        let mut y: [F; N] = y.clone();
        self.permute_in_place(&mut x, &mut y);
        (x, y)
    }
}

impl<F: PrimeField> ApplicableMDSMatrix<F, 2> for MDSMatrix<F, 2> {
    fn from_generator(generator: &F) -> Self {
        // The matrix is:
        //     ⌈ 1     g       ⌉
        //     ⌊ g     g^2 + 1 ⌋
        Self([
            [F::ONE, *generator],
            [*generator, generator.square().add(F::ONE)],
        ])
    }

    fn permute_in_place(&self, x: &mut [F; 2], y: &mut [F; 2]) {
        // Reminder: a different matrix is applied to x and y
        // The one for y has a simple word permutation.

        let old_x = x.clone();
        for i in 0..2 {
            x[i] = F::ZERO;
            for j in 0..2 {
                x[i] += &(self.0[i][j] * old_x[j]);
            }
        }

        // y has a simple word permutation.
        let old_y = [y[1], y[0]];
        for i in 0..2 {
            y[i] = F::ZERO;
            for j in 0..2 {
                y[i] += &(self.0[i][j] * old_y[j]);
            }
        }
    }
}
