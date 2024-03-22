use ark_ff::{batch_inversion, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::EvaluationDomain;
use ark_std::cfg_into_iter;
use ark_std::{cmp::min, ops::*};
use itertools::Itertools;
use rand_chacha::rand_core::{CryptoRng, RngCore};

#[cfg(feature = "parallel")]
use rayon::{iter::IntoParallelIterator, prelude::ParallelIterator};

use super::{
    constraint_system::ConstraintSystem,
    indexer::{PlonkProof, PlonkProverParams, PlonkVerifierParams},
};
use crate::errors::UzkgeError;
use crate::poly_commit::pcs::HomomorphicPolyComElem;
use crate::poly_commit::{field_polynomial::FpPolynomial, pcs::PolyComScheme};

/// The data structure for challenges in Plonk.
#[derive(Default)]
pub(super) struct PlonkChallenges<F> {
    challenges: Vec<F>,
}

impl<F: PrimeField> PlonkChallenges<F> {
    /// Create a challenges with capacity 4.
    pub(super) fn new() -> PlonkChallenges<F> {
        PlonkChallenges {
            challenges: Vec::with_capacity(4),
        }
    }

    /// Insert beta and gamma.
    pub(super) fn insert_beta_gamma(&mut self, beta: F, gamma: F) -> Result<(), UzkgeError> {
        if self.challenges.is_empty() {
            self.challenges.push(beta);
            self.challenges.push(gamma);
            Ok(())
        } else {
            Err(UzkgeError::ChallengeError)
        }
    }

    /// Insert alpha.
    pub(super) fn insert_alpha(&mut self, alpha: F) -> Result<(), UzkgeError> {
        if self.challenges.len() == 2 {
            self.challenges.push(alpha);
            Ok(())
        } else {
            Err(UzkgeError::ChallengeError)
        }
    }

    /// Insert zeta.
    pub(super) fn insert_zeta(&mut self, zeta: F) -> Result<(), UzkgeError> {
        if self.challenges.len() == 3 {
            self.challenges.push(zeta);
            Ok(())
        } else {
            Err(UzkgeError::ChallengeError)
        }
    }

    /// Insert u.
    pub(super) fn insert_u(&mut self, u: F) -> Result<(), UzkgeError> {
        if self.challenges.len() == 4 {
            self.challenges.push(u);
            Ok(())
        } else {
            Err(UzkgeError::ChallengeError)
        }
    }

    /// Return beta and gamma.
    pub(super) fn get_beta_gamma(&self) -> Result<(&F, &F), UzkgeError> {
        if self.challenges.len() > 1 {
            Ok((&self.challenges[0], &self.challenges[1]))
        } else {
            Err(UzkgeError::ChallengeError)
        }
    }

    /// Return alpha.
    pub(super) fn get_alpha(&self) -> Result<&F, UzkgeError> {
        if self.challenges.len() > 2 {
            Ok(&self.challenges[2])
        } else {
            Err(UzkgeError::ChallengeError)
        }
    }

    /// Return zeta.
    pub(super) fn get_zeta(&self) -> Result<&F, UzkgeError> {
        if self.challenges.len() > 3 {
            Ok(&self.challenges[3])
        } else {
            Err(UzkgeError::ChallengeError)
        }
    }

    /// Return u.
    pub(super) fn get_u(&self) -> Result<&F, UzkgeError> {
        if self.challenges.len() > 4 {
            Ok(&self.challenges[4])
        } else {
            Err(UzkgeError::ChallengeError)
        }
    }
}

/// Return the PI polynomial.
pub(super) fn pi_poly<PCS: PolyComScheme, E: EvaluationDomain<PCS::Field>>(
    prover_params: &PlonkProverParams<PCS>,
    pi: &[PCS::Field],
    domain: &E,
) -> FpPolynomial<PCS::Field> {
    let mut evals = Vec::with_capacity(prover_params.verifier_params.cs_size);
    for (i, _) in prover_params.group.iter().enumerate() {
        if let Some((pos, _)) = prover_params
            .verifier_params
            .public_vars_constraint_indices
            .iter()
            .find_position(|&&x| x == i)
        {
            evals.push(pi[pos])
        } else {
            evals.push(PCS::Field::zero());
        }
    }

    FpPolynomial::ifft_with_domain(domain, &evals)
}

/// Add a random degree `num_hide_points`+`zeroing_degree` polynomial
/// that vanishes on X^{zeroing_degree} -1. Goal is to randomize
/// `polynomial` maintaining output values for elements in a sub group
/// of order N. Eg, when num_hide_points is 1, then it adds
/// (r1 + r2*X) * (X^zeroing_degree - 1) to `polynomial.
pub(super) fn hide_polynomial<R: CryptoRng + RngCore, F: PrimeField>(
    prng: &mut R,
    polynomial: &mut FpPolynomial<F>,
    hiding_degree: usize,
    zeroing_degree: usize,
) -> Vec<F> {
    let mut blinds = Vec::new();
    for i in 0..hiding_degree {
        let mut blind = F::rand(prng);
        blinds.push(blind);
        polynomial.add_coef_assign(&blind, i);
        blind = blind.neg();
        polynomial.add_coef_assign(&blind, zeroing_degree + i);
    }
    blinds
}

/// Build the z polynomial, by interpolating
/// z(\omega^{i+1}) = z(\omega^i)\prod_{j=1}^{n_wires_per_gate}(fj(\omega^i)
/// + \beta * k_j * \omega^i +\gamma)/(fj(\omega^i) + \beta * perm_j(\omega^i) +\gamma)
/// and setting z(1) = 1 for the base case
pub(super) fn z_poly<PCS: PolyComScheme, CS: ConstraintSystem<PCS::Field>>(
    prover_params: &PlonkProverParams<PCS>,
    w: &[PCS::Field],
    challenges: &PlonkChallenges<PCS::Field>,
) -> FpPolynomial<PCS::Field> {
    let n_wires_per_gate = CS::n_wires_per_gate();
    let (beta, gamma) = challenges.get_beta_gamma().unwrap();
    let perm = &prover_params.permutation;
    let n_constraints = w.len() / n_wires_per_gate;
    let group = &prover_params.group[..];

    // computes permutation values
    let p_of_x =
        |perm_value: usize, n: usize, group: &[PCS::Field], k: &[PCS::Field]| -> PCS::Field {
            for (i, ki) in k.iter().enumerate().skip(1) {
                if perm_value < (i + 1) * n && perm_value >= i * n {
                    return ki.mul(&group[perm_value % n]);
                }
            }
            k[0].mul(&group[perm_value])
        };

    let k = &prover_params.verifier_params.k;

    let res = cfg_into_iter!(0..n_constraints - 1)
        .map(|i| {
            // 1. numerator = prod_{j=1..n_wires_per_gate}(fj(\omega^i) + \beta * k_j * \omega^i + \gamma)
            // 2. denominator = prod_{j=1..n_wires_per_gate}(fj(\omega^i) + \beta * permj(\omega^i) +\gamma)
            let mut numerator = PCS::Field::one();
            let mut denominator = PCS::Field::one();
            for j in 0..n_wires_per_gate {
                let k_x = k[j].mul(&group[i]);
                let f_x = &w[j * n_constraints + i];
                let f_plus_beta_id_plus_gamma = &f_x.add(gamma).add(&beta.mul(&k_x));
                numerator.mul_assign(f_plus_beta_id_plus_gamma);

                let p_x = p_of_x(perm[j * n_constraints + i], n_constraints, group, k);
                let f_plus_beta_perm_plus_gamma = f_x.add(gamma).add(&beta.mul(&p_x));
                denominator.mul_assign(f_plus_beta_perm_plus_gamma);
            }

            (numerator, denominator)
        })
        .collect::<Vec<(PCS::Field, PCS::Field)>>();

    let (numerators, mut denominators): (Vec<PCS::Field>, Vec<PCS::Field>) =
        res.iter().cloned().unzip();

    batch_inversion(&mut denominators);

    let mut prev = PCS::Field::one();
    let mut z_evals = vec![];
    z_evals.push(prev);
    for (x, y) in denominators.iter().zip(numerators.iter()) {
        prev.mul_assign(y.mul(x));
        z_evals.push(prev);
    }

    // interpolate the polynomial
    FpPolynomial::from_coefs(z_evals)
}

/// Compute the t polynomial.
pub(super) fn t_poly<PCS: PolyComScheme, CS: ConstraintSystem<PCS::Field>>(
    cs: &CS,
    prover_params: &PlonkProverParams<PCS>,
    w_polys: &[FpPolynomial<PCS::Field>],
    #[cfg(feature = "shuffle")] w_sel_polys: &[FpPolynomial<PCS::Field>],
    z: &FpPolynomial<PCS::Field>,
    challenges: &PlonkChallenges<PCS::Field>,
    pi: &FpPolynomial<PCS::Field>,
) -> Result<FpPolynomial<PCS::Field>, UzkgeError> {
    let n = cs.size();
    let m = cs.quot_eval_dom_size();
    let factor = m / n;
    if n * factor != m {
        return Err(UzkgeError::SetupError);
    }
    let one = PCS::Field::ONE;

    let domain_m = FpPolynomial::<PCS::Field>::quotient_evaluation_domain(m)
        .ok_or(UzkgeError::GroupNotFound(n))?;
    let k = &prover_params.verifier_params.k;

    let mut z_h_inv_coset_evals: Vec<PCS::Field> = Vec::with_capacity(factor);
    let group_gen_pow_n = domain_m.group_gen.pow(&[n as u64]);
    let mut multiplier = k[1].pow(&[n as u64]);
    for _ in 0..factor {
        let eval = multiplier.sub(&one);
        z_h_inv_coset_evals.push(eval);
        multiplier.mul_assign(&group_gen_pow_n);
    }
    batch_inversion(&mut z_h_inv_coset_evals);
    let z_h_inv_coset_evals = z_h_inv_coset_evals.iter().map(|x| *x).collect::<Vec<_>>();

    // Compute the evaluations of w/w_sel/pi/z polynomials on the coset k[1] * <root_m>.
    let w_polys_coset_evals: Vec<Vec<PCS::Field>> = w_polys
        .iter()
        .map(|poly| poly.coset_fft_with_domain(&domain_m, &k[1]))
        .collect();
    #[cfg(feature = "shuffle")]
    let w_sel_polys_coset_evals: Vec<Vec<PCS::Field>> = w_sel_polys
        .iter()
        .map(|poly| poly.coset_fft_with_domain(&domain_m, &k[1]))
        .collect();
    let pi_coset_evals = pi.coset_fft_with_domain(&domain_m, &k[1]);
    let z_coset_evals = z.coset_fft_with_domain(&domain_m, &k[1]);

    #[cfg(feature = "shuffle")]
    let edwards_a: <PCS as PolyComScheme>::Field = cs.get_edwards_a();

    // Compute the evaluations of the quotient polynomial on the coset.
    let (beta, gamma) = challenges.get_beta_gamma().unwrap();

    let alpha = challenges.get_alpha().unwrap();
    let alpha_pow_2 = alpha.mul(alpha);
    let alpha_pow_3 = alpha_pow_2.mul(alpha);
    let alpha_pow_4 = alpha_pow_3.mul(alpha);
    let alpha_pow_5 = alpha_pow_4.mul(alpha);
    let alpha_pow_6 = alpha_pow_5.mul(alpha);
    let alpha_pow_7 = alpha_pow_6.mul(alpha);
    let alpha_pow_8 = alpha_pow_7.mul(alpha);
    let alpha_pow_9 = alpha_pow_8.mul(alpha);

    let t_coset_evals = cfg_into_iter!(0..m)
        .map(|point| {
            let w_vals: Vec<&PCS::Field> = w_polys_coset_evals
                .iter()
                .map(|poly_coset_evals| &poly_coset_evals[point])
                .collect();
            let q_vals: Vec<&PCS::Field> = prover_params
                .q_coset_evals
                .iter()
                .map(|poly_coset_evals| &poly_coset_evals[point])
                .collect();
            // q * w
            let term1 = CS::eval_gate_func(&w_vals, &q_vals, &pi_coset_evals[point]).unwrap();

            // alpha * [z(X)\prod_j (fj(X) + beta * kj * X + gamma)]
            let mut term2 = alpha.mul(&z_coset_evals[point]);
            for j in 0..CS::n_wires_per_gate() {
                let tmp = w_polys_coset_evals[j][point]
                    .add(gamma)
                    .add(&beta.mul(&k[j].mul(&prover_params.coset_quotient[point])));
                term2.mul_assign(&tmp);
            }

            // alpha * [z(\omega * X)\prod_j (fj(X) + beta * perm_j(X) + gamma)]
            let mut term3 = alpha.mul(&z_coset_evals[(point + factor) % m]);
            for (w_poly_coset_evals, s_coset_evals) in w_polys_coset_evals
                .iter()
                .zip(prover_params.s_coset_evals.iter())
            {
                let tmp = &w_poly_coset_evals[point]
                    .add(gamma)
                    .add(&beta.mul(&s_coset_evals[point]));
                term3.mul_assign(tmp);
            }

            // alpha^2 * (z(X) - 1) * L_1(X)
            let term4 = alpha_pow_2
                .mul(&prover_params.l1_coset_evals[point])
                .mul(&z_coset_evals[point].sub(&one));

            let qb_eval_point = prover_params.qb_coset_eval[point];

            // alpha^3 * qb(X) (w[1] (w[1] - 1))
            let w1_eval_point = w_polys_coset_evals[1][point];
            let term5 = alpha_pow_3
                .mul(&qb_eval_point)
                .mul(&w1_eval_point)
                .mul(&w1_eval_point.sub(&one));

            // alpha^4 * qb(X) (w[2] (w[2] - 1))
            let w2_eval_point = w_polys_coset_evals[2][point];
            let term6 = alpha_pow_4
                .mul(&qb_eval_point)
                .mul(&w2_eval_point)
                .mul(&w2_eval_point.sub(&one));

            // alpha^5 * qb(X) (w[3] (w[3] - 1))
            let w3_eval_point = w_polys_coset_evals[3][point];
            let term7 = alpha_pow_5
                .mul(&qb_eval_point)
                .mul(&w3_eval_point)
                .mul(&w3_eval_point.sub(&one));

            let w0_eval_point = w_polys_coset_evals[0][point];
            let wo_eval_point = w_polys_coset_evals[4][point];
            let w0_eval_point_next = w_polys_coset_evals[0][(point + factor) % m];
            let w1_eval_point_next = w_polys_coset_evals[1][(point + factor) % m];
            let w2_eval_point_next = w_polys_coset_evals[2][(point + factor) % m];
            let q_prk1_eval_point = prover_params.q_prk_coset_evals[0][point];
            let q_prk2_eval_point = prover_params.q_prk_coset_evals[1][point];
            let q_prk3_eval_point = prover_params.q_prk_coset_evals[2][point];
            let q_prk4_eval_point = prover_params.q_prk_coset_evals[3][point];
            let g = prover_params.verifier_params.anemoi_generator;
            let g_square_plus_one = g.square().add(one);
            let g_inv = prover_params.verifier_params.anemoi_generator_inv;
            let five = &[5u64];

            let w3_w0_eval_point = w0_eval_point + w3_eval_point;
            let w2_w1_eval_point = w1_eval_point + w2_eval_point;

            let w3_2w0_eval_point = w0_eval_point + w3_w0_eval_point;
            let w2_2w1_eval_point = w1_eval_point + w2_w1_eval_point;

            let tmp = w3_w0_eval_point + &(g * &w2_w1_eval_point) + &q_prk3_eval_point;

            // - alpha^6 * q_{prk3} *
            //  (
            //    (w[0] + w[3] + g * (w[1] + w[2]) + q_{prk3} - w_next[2]) ^ 5
            //    + g * (w[0] + w[3] + g * (w[1] + w[2]) + q_{prk3}) ^ 2
            //    - (2w[0] + w[3] + g * (2w[1] + w[2]) + q_{prk1})
            //  )
            let term8 = alpha_pow_6.mul(&q_prk3_eval_point).mul(
                (tmp - &w2_eval_point_next).pow(five) + &(g * tmp.square())
                    - &(w3_2w0_eval_point + g * w2_2w1_eval_point + &q_prk1_eval_point),
            );
            // - alpha^8 * q_{prk3} *
            //  (
            //    (w[0] + w[3] + g * (w[1] + w[2]) + q_{prk3} - w_next[2]) ^ 5
            //    + g * w_next[2] ^ 2 + g^-1
            //    - w_next[0]
            //  )
            let term10 = alpha_pow_8.mul(&q_prk3_eval_point).mul(
                (tmp - &w2_eval_point_next).pow(five) + &(g * w2_eval_point_next.square()) + g_inv
                    - &w0_eval_point_next,
            );

            // - alpha^7 * q_{prk3} *
            //  (
            //    (g * (w[0] + w[3]) + (g^2 + 1) * (w[1] + w[2]) + q_{prk4} - w[4]) ^ 5
            //    + g * (g * (w[0] + w[3]) + (g^2 + 1) * (w[1] + w[2]) + q_{prk4}) ^ 2
            //    - (g * (2w[0] + w[3]) + (g^2 + 1) * (2w[1] + w[2]) + q_{prk2})
            //  )
            let tmp = g * &w3_w0_eval_point
                + &(g_square_plus_one * &w2_w1_eval_point)
                + &q_prk4_eval_point;
            let term9 = alpha_pow_7.mul(&q_prk3_eval_point).mul(
                (tmp - &wo_eval_point).pow(five) + &(g * tmp.square())
                    - &(g * &w3_2w0_eval_point
                        + g_square_plus_one * &w2_2w1_eval_point
                        + &q_prk2_eval_point),
            );

            // - alpha^9 * q_{prk3} *
            //  (
            //    (g * (w[0] + w[3]) + (g^2 + 1) * (w[1] + w[2]) + q_{prk4} - w[4]) ^ 5
            //    + g * w[4] ^ 2 + g^-1
            //    - w_next[1]
            //  )
            let term11 = alpha_pow_9.mul(&q_prk3_eval_point).mul(
                (tmp - &wo_eval_point).pow(five) + &(g * wo_eval_point.square()) + g_inv
                    - &w1_eval_point_next,
            );

            #[cfg(feature = "shuffle")]
            let (term12, term13, term14, term15, term16, term17, term18) = {
                let alpha_pow_10 = alpha_pow_9.mul(alpha);
                let alpha_pow_11 = alpha_pow_10.mul(alpha);
                let alpha_pow_12 = alpha_pow_11.mul(alpha);
                let alpha_pow_13 = alpha_pow_12.mul(alpha);
                let alpha_pow_14 = alpha_pow_13.mul(alpha);
                let alpha_pow_15 = alpha_pow_14.mul(alpha);
                let alpha_pow_16 = alpha_pow_15.mul(alpha);

                let w_sel0_eval_point = w_sel_polys_coset_evals[0][point];
                let w_sel1_eval_point = w_sel_polys_coset_evals[1][point];
                let w_sel2_eval_point = w_sel_polys_coset_evals[2][point];
                let q_pk_x_00_eval_point = prover_params.q_shuffle_public_key_coset_evals[0][point];
                let q_pk_x_01_eval_point = prover_params.q_shuffle_public_key_coset_evals[1][point];
                let q_pk_x_10_eval_point = prover_params.q_shuffle_public_key_coset_evals[2][point];
                let q_pk_x_11_eval_point = prover_params.q_shuffle_public_key_coset_evals[3][point];
                let q_pk_y_00_eval_point = prover_params.q_shuffle_public_key_coset_evals[4][point];
                let q_pk_y_01_eval_point = prover_params.q_shuffle_public_key_coset_evals[5][point];
                let q_pk_y_10_eval_point = prover_params.q_shuffle_public_key_coset_evals[6][point];
                let q_pk_y_11_eval_point = prover_params.q_shuffle_public_key_coset_evals[7][point];
                let q_pk_dxy_00_eval_point =
                    prover_params.q_shuffle_public_key_coset_evals[8][point];
                let q_pk_dxy_01_eval_point =
                    prover_params.q_shuffle_public_key_coset_evals[9][point];
                let q_pk_dxy_10_eval_point =
                    prover_params.q_shuffle_public_key_coset_evals[10][point];
                let q_pk_dxy_11_eval_point =
                    prover_params.q_shuffle_public_key_coset_evals[11][point];
                let q_g_x_00_eval_point = prover_params.q_shuffle_generator_coset_evals[0][point];
                let q_g_x_01_eval_point = prover_params.q_shuffle_generator_coset_evals[1][point];
                let q_g_x_10_eval_point = prover_params.q_shuffle_generator_coset_evals[2][point];
                let q_g_x_11_eval_point = prover_params.q_shuffle_generator_coset_evals[3][point];
                let q_g_y_00_eval_point = prover_params.q_shuffle_generator_coset_evals[4][point];
                let q_g_y_01_eval_point = prover_params.q_shuffle_generator_coset_evals[5][point];
                let q_g_y_10_eval_point = prover_params.q_shuffle_generator_coset_evals[6][point];
                let q_g_y_11_eval_point = prover_params.q_shuffle_generator_coset_evals[7][point];
                let q_g_dxy_00_eval_point = prover_params.q_shuffle_generator_coset_evals[8][point];
                let q_g_dxy_01_eval_point = prover_params.q_shuffle_generator_coset_evals[9][point];
                let q_g_dxy_10_eval_point =
                    prover_params.q_shuffle_generator_coset_evals[10][point];
                let q_g_dxy_11_eval_point =
                    prover_params.q_shuffle_generator_coset_evals[11][point];
                let q_ecc = prover_params.q_ecc_coset_eval[point];

                let sel_00 = (one - w_sel0_eval_point) * (one - w_sel1_eval_point) + q_ecc - one;
                let sel_01 = w_sel0_eval_point * (one - w_sel1_eval_point);
                let sel_10 = (one - w_sel0_eval_point) * w_sel1_eval_point;
                let sel_11 = w_sel0_eval_point * w_sel1_eval_point;

                // alpha^10 *
                // ((1 - w_sel[0]) * (1 - w_sel[1]) + q_{ecc} - 1) * (w_sel[2] * w_next[0] - w_sel[2] * w[0] * q_{pk_y_00} - w[1] * q_{pk_x_00} + w[0] * w[1] * w_next[0] *  q_{pk_dxy_00}) *
                // w_sel[0] *  (1 - w_sel[1]) * (w_sel[2] * w_next[0] - w_sel[2] * w[0] * q_{pk_y_01} - w[1] * q_{pk_x_01} + w[0] * w[1] * w_next[0] *  q_{pk_dxy_01})
                // (1 - w_sel[0]) *  w_sel[1] * (w_sel[2] * w_next[0] - w_sel[2] * w[0] * q_{pk_y_10} - w[1] * q_{pk_x_10} + w[0] * w[1] * w_next[0] *  q_{pk_dxy_10})
                // w_sel[0] *  w_sel[1] * (w_sel[2] * w_next[0] - w_sel[2] * w[0] * q_{pk_y_11} - w[1] * q_{pk_x_11} + w[0] * w[1] * w_next[0] *  q_{pk_dxy_11})
                let term12 = alpha_pow_10.mul(
                    sel_00
                        * (w_sel2_eval_point * w0_eval_point_next
                            - w_sel2_eval_point * w0_eval_point * q_pk_y_00_eval_point
                            - w1_eval_point * q_pk_x_00_eval_point
                            + w0_eval_point
                                * w1_eval_point
                                * w0_eval_point_next
                                * q_pk_dxy_00_eval_point)
                        + sel_01
                            * (w_sel2_eval_point * w0_eval_point_next
                                - w_sel2_eval_point * w0_eval_point * q_pk_y_01_eval_point
                                - w1_eval_point * q_pk_x_01_eval_point
                                + w0_eval_point
                                    * w1_eval_point
                                    * w0_eval_point_next
                                    * q_pk_dxy_01_eval_point)
                        + sel_10
                            * (w_sel2_eval_point * w0_eval_point_next
                                - w_sel2_eval_point * w0_eval_point * q_pk_y_10_eval_point
                                - w1_eval_point * q_pk_x_10_eval_point
                                + w0_eval_point
                                    * w1_eval_point
                                    * w0_eval_point_next
                                    * q_pk_dxy_10_eval_point)
                        + sel_11
                            * (w_sel2_eval_point * w0_eval_point_next
                                - w_sel2_eval_point * w0_eval_point * q_pk_y_11_eval_point
                                - w1_eval_point * q_pk_x_11_eval_point
                                + w0_eval_point
                                    * w1_eval_point
                                    * w0_eval_point_next
                                    * q_pk_dxy_11_eval_point),
                );

                // alpha^11 *
                // ((1 - w_sel[0]) * (1 - w_sel[1]) + q_{ecc} - 1) * (w_sel[2] * w_next[1] + a * w[0] * q_{pk_x_00} - w_sel[2] * w[1] * q_{pk_y_00} - w[0] * w[1] * w_next[1] *  q_{pk_dxy_00}) +
                // w_sel[0] *  (1 - w_sel[1]) * (w_sel[2] * w_next[1] + a * w[0] * q_{pk_x_01} - w_sel[2] * w[1] * q_{pk_y_01} - w[0] * w[1] * w_next[1] *  q_{pk_dxy_01}) +
                // (1 - w_sel[0]) *  w_sel[1] * (w_sel[2] * w_next[1] + a * w[0] * q_{pk_x_10} - w_sel[2] * w[1] * q_{pk_y_10} - w[0] * w[1] * w_next[1] *  q_{pk_dxy_10}) +
                // w_sel[0] *  w_sel[1] * (w_sel[2] * w_next[1] + a * w[0] * q_{pk_x_11} - w_sel[2] * w[1] * q_{pk_y_11} - w[0] * w[1] * w_next[1] *  q_{pk_dxy_11}) +
                let term13 = alpha_pow_11.mul(
                    sel_00
                        * (w_sel2_eval_point * w1_eval_point_next
                            + w0_eval_point * edwards_a * q_pk_x_00_eval_point
                            - w_sel2_eval_point * w1_eval_point * q_pk_y_00_eval_point
                            - w0_eval_point
                                * w1_eval_point
                                * w1_eval_point_next
                                * q_pk_dxy_00_eval_point)
                        + sel_01
                            * (w_sel2_eval_point * w1_eval_point_next
                                + w0_eval_point * edwards_a * q_pk_x_01_eval_point
                                - w_sel2_eval_point * w1_eval_point * q_pk_y_01_eval_point
                                - w0_eval_point
                                    * w1_eval_point
                                    * w1_eval_point_next
                                    * q_pk_dxy_01_eval_point)
                        + sel_10
                            * (w_sel2_eval_point * w1_eval_point_next
                                + w0_eval_point * edwards_a * q_pk_x_10_eval_point
                                - w_sel2_eval_point * w1_eval_point * q_pk_y_10_eval_point
                                - w0_eval_point
                                    * w1_eval_point
                                    * w1_eval_point_next
                                    * q_pk_dxy_10_eval_point)
                        + sel_11
                            * (w_sel2_eval_point * w1_eval_point_next
                                + w0_eval_point * edwards_a * q_pk_x_11_eval_point
                                - w_sel2_eval_point * w1_eval_point * q_pk_y_11_eval_point
                                - w0_eval_point
                                    * w1_eval_point
                                    * w1_eval_point_next
                                    * q_pk_dxy_11_eval_point),
                );

                // alpha^12 *
                // ((1 - w_sel[0]) * (1 - w_sel[1]) + q_{ecc} - 1) * (w_sel[2] * w_next[2] - w_sel[2] * w[2] * q_{g_y_00} - w[3] * q_{g_x_00} + w[2] * w[3] * w_next[2] *  q_{g_dxy_00}) +
                // w_sel[0] *  (1 - w_sel[1]) * (w_sel[2] * w_next[2] - w_sel[2] * w[2] * q_{g_y_01} - w[3] * q_{g_x_01} + w[2] * w[3] * w_next[2] *  q_{g_dxy_01}) +
                // (1 - w_sel[0]) *  w_sel[1] * (w_sel[2] * w_next[2] - w_sel[2] * w[2] * q_{g_y_10} - w[3] * q_{g_x_10} + w[2] * w[3] * w_next[2] *  q_{g_dxy_10}) +
                // w_sel[0] *  w_sel[1] * (w_sel[2] * w_next[2] - w_sel[2] * w[2] * q_{g_y_11} - w[3] * q_{g_x_11} + w[2] * w[3] * w_next[2] *  q_{g_dxy_11}) +
                let term14 = alpha_pow_12.mul(
                    sel_00
                        * (w_sel2_eval_point * w2_eval_point_next
                            - w_sel2_eval_point * w2_eval_point * q_g_y_00_eval_point
                            - w3_eval_point * q_g_x_00_eval_point
                            + w2_eval_point
                                * w3_eval_point
                                * w2_eval_point_next
                                * q_g_dxy_00_eval_point)
                        + sel_01
                            * (w_sel2_eval_point * w2_eval_point_next
                                - w_sel2_eval_point * w2_eval_point * q_g_y_01_eval_point
                                - w3_eval_point * q_g_x_01_eval_point
                                + w2_eval_point
                                    * w3_eval_point
                                    * w2_eval_point_next
                                    * q_g_dxy_01_eval_point)
                        + sel_10
                            * (w_sel2_eval_point * w2_eval_point_next
                                - w_sel2_eval_point * w2_eval_point * q_g_y_10_eval_point
                                - w3_eval_point * q_g_x_10_eval_point
                                + w2_eval_point
                                    * w3_eval_point
                                    * w2_eval_point_next
                                    * q_g_dxy_10_eval_point)
                        + sel_11
                            * (w_sel2_eval_point * w2_eval_point_next
                                - w_sel2_eval_point * w2_eval_point * q_g_y_11_eval_point
                                - w3_eval_point * q_g_x_11_eval_point
                                + w2_eval_point
                                    * w3_eval_point
                                    * w2_eval_point_next
                                    * q_g_dxy_11_eval_point),
                );

                // alpha^13 *
                // ((1 - w_sel[0]) * (1 - w_sel[1]) + q_{ecc} - 1) * (w_sel[2] * w[4] + a * w[2] * q_{g_x_00} - w_sel[2] * w[3] * q_{g_y_00} + w[2] * w[3] * w[4] *  q_{pk_gxy_00}) +
                // w_sel[0] *  (1 - w_sel[1]) * (w_sel[2] * w[4] + a * w[2] * q_{g_x_01} - w_sel[2] * w[3] * q_{g_y_01} + w[2] * w[3] * w[4] *  q_{pk_gxy_01}) +
                // (1 - w_sel[0]) *  w_sel[1] * (w_sel[2] * w[4] + a * w[2] * q_{g_x_10} - w_sel[2] * w[3] * q_{g_y_10} + w[2] * w[3] * w[4] *  q_{pk_gxy_10}) +
                // w_sel[0] *  w_sel[1] * (w_sel[2] * w[4] + a * w[2] * q_{g_x_11} - w_sel[2] * w[3] * q_{g_y_11} + w[2] * w[3] * w[4] *  q_{pk_gxy_11}) +
                let term15 = alpha_pow_13.mul(
                    sel_00
                        * (w_sel2_eval_point * wo_eval_point
                            + w2_eval_point * edwards_a * q_g_x_00_eval_point
                            - w_sel2_eval_point * w3_eval_point * q_g_y_00_eval_point
                            - w2_eval_point
                                * w3_eval_point
                                * wo_eval_point
                                * q_g_dxy_00_eval_point)
                        + sel_01
                            * (w_sel2_eval_point * wo_eval_point
                                + w2_eval_point * edwards_a * q_g_x_01_eval_point
                                - w_sel2_eval_point * w3_eval_point * q_g_y_01_eval_point
                                - w2_eval_point
                                    * w3_eval_point
                                    * wo_eval_point
                                    * q_g_dxy_01_eval_point)
                        + sel_10
                            * (w_sel2_eval_point * wo_eval_point
                                + w2_eval_point * edwards_a * q_g_x_10_eval_point
                                - w_sel2_eval_point * w3_eval_point * q_g_y_10_eval_point
                                - w2_eval_point
                                    * w3_eval_point
                                    * wo_eval_point
                                    * q_g_dxy_10_eval_point)
                        + sel_11
                            * (w_sel2_eval_point * wo_eval_point
                                + w2_eval_point * edwards_a * q_g_x_11_eval_point
                                - w_sel2_eval_point * w3_eval_point * q_g_y_11_eval_point
                                - w2_eval_point
                                    * w3_eval_point
                                    * wo_eval_point
                                    * q_g_dxy_11_eval_point),
                );

                // alpha^14 * (q_{ecc} * w_sel[0] * (1 - w_sel[0]) + (1 - q_{ecc}) *  w_sel[0])
                let term16 = alpha_pow_14.mul(
                    q_ecc * w_sel0_eval_point * (one - w_sel0_eval_point)
                        + (one - q_ecc) * w_sel0_eval_point,
                );
                // alpha^15 * (q_{ecc} * w_sel[1] * (1 - w_sel[1]) + (1 - q_{ecc}) *  w_sel[1])
                let term17 = alpha_pow_15.mul(
                    q_ecc * w_sel1_eval_point * (one - w_sel1_eval_point)
                        + (one - q_ecc) * w_sel1_eval_point,
                );
                // alpha^16 * q_{ecc} * (1 + w_sel[2])  * (1 - w_sel[2])
                let term18 =
                    alpha_pow_16.mul(q_ecc * (one + w_sel2_eval_point) * (one - w_sel2_eval_point));

                (term12, term13, term14, term15, term16, term17, term18)
            };

            let numerator = term1
                .add(&term2)
                .add(&term4.sub(&term3))
                .add(&term5)
                .add(&term6)
                .add(&term7)
                .sub(&term8)
                .sub(&term9)
                .sub(&term10)
                .sub(&term11);

            #[cfg(feature = "shuffle")]
            let numerator = {
                numerator
                    .add(&term12)
                    .add(&term13)
                    .add(&term14)
                    .add(&term15)
                    .add(&term16)
                    .add(&term17)
                    .add(&term18)
            };

            numerator.mul(&z_h_inv_coset_evals[point % factor])
        })
        .collect::<Vec<PCS::Field>>();

    let k_inv = k[1].inverse().ok_or(UzkgeError::DivisionByZero)?;

    Ok(FpPolynomial::coset_ifft_with_domain(
        &domain_m,
        &t_coset_evals,
        &k_inv,
    ))
}

/// Compute r polynomial or commitment.
fn r_poly_or_comm<F: PrimeField, PCSType: HomomorphicPolyComElem<Scalar = F>>(
    w: &[F],
    q_polys_or_comms: &[PCSType],
    qb_poly_or_comm: &PCSType,
    q_prk1_poly_or_comm: &PCSType,
    q_prk2_poly_or_comm: &PCSType,
    #[cfg(feature = "shuffle")] q_shuffle_generator_polys_or_comms: &[PCSType],
    #[cfg(feature = "shuffle")] q_shuffle_public_key_polys_or_comms: &[PCSType],
    #[cfg(feature = "shuffle")] q_ecc_poly_eval_zeta: &F,
    #[cfg(feature = "shuffle")] w_sel_polys_eval_zeta: &[&F],
    k: &[F],
    #[cfg(feature = "shuffle")] edwards_a: &F,
    last_s_poly_or_comm: &PCSType,
    z_poly_or_comm: &PCSType,
    w_polys_eval_zeta: &[&F],
    #[cfg(feature = "shuffle")] w_polys_eval_zeta_omega: &[&F],
    s_polys_eval_zeta: &[&F],
    q_prk3_eval_zeta: &F,
    z_eval_zeta_omega: &F,
    challenges: &PlonkChallenges<F>,
    t_polys_or_comms: &[PCSType],
    first_lagrange_eval_zeta: &F,
    z_h_eval_zeta: &F,
    n_t_polys: usize,
) -> PCSType {
    let one = F::one();
    let (beta, gamma) = challenges.get_beta_gamma().unwrap();
    let alpha = challenges.get_alpha().unwrap();
    let zeta = challenges.get_zeta().unwrap();

    let alpha_pow_2 = alpha.mul(alpha);
    let alpha_pow_3 = alpha_pow_2.mul(alpha);
    let alpha_pow_4 = alpha_pow_3.mul(alpha);
    let alpha_pow_5 = alpha_pow_4.mul(alpha);
    let alpha_pow_6 = alpha_pow_5.mul(alpha);
    let alpha_pow_7 = alpha_pow_6.mul(alpha);

    // 1. sum_{i=1..n_selectors} wi * qi(X)
    let mut l = q_polys_or_comms[0].mul(&w[0]);
    for i in 1..q_polys_or_comms.len() {
        l.add_assign(&q_polys_or_comms[i].mul(&w[i]));
    }

    // 2. z(X) [ alpha * prod_{j=1..n_wires_per_gate} (fj(zeta) + beta * kj * zeta + gamma)
    //              + alpha^2 * L1(zeta)]
    let z_scalar =
        compute_z_scalar_in_r(w_polys_eval_zeta, k, challenges, first_lagrange_eval_zeta);
    l.add_assign(&z_poly_or_comm.mul(&z_scalar));

    // 3. - perm_{n_wires_per_gate}(X) [alpha * z(zeta * omega) * beta
    //    * prod_{j=1..n_wires_per_gate-1}(fj(zeta) + beta * perm_j(zeta) + gamma)]
    let mut s_last_poly_scalar = alpha.mul(&z_eval_zeta_omega.mul(beta));
    for i in 0..w_polys_eval_zeta.len() - 1 {
        let tmp = w_polys_eval_zeta[i]
            .add(&beta.mul(s_polys_eval_zeta[i]))
            .add(gamma);
        s_last_poly_scalar.mul_assign(&tmp);
    }
    l.sub_assign(&last_s_poly_or_comm.mul(&s_last_poly_scalar));

    // 4. + qb(X) * (w[1] (w[1] - 1) * alpha^3 + w[2] (w[2] - 1) * alpha^4 + w[3] (w[3] - 1) * alpha^5)
    let w1_part = w[1].mul(&(w[1] - &one)).mul(&alpha_pow_3);
    let w2_part = w[2].mul(&(w[2] - &one)).mul(&alpha_pow_4);
    let w3_part = w[3].mul(&(w[3] - &one)).mul(&alpha_pow_5);
    l.add_assign(&qb_poly_or_comm.mul(&w1_part.add(w2_part).add(w3_part)));

    // 5. + q_{prk3}(eval zeta) * (q_{prk1}(X) * alpha^6 + q_{prk2}(X) * alpha ^ 7)
    l.add_assign(&q_prk1_poly_or_comm.mul(&q_prk3_eval_zeta.mul(alpha_pow_6)));
    l.add_assign(&q_prk2_poly_or_comm.mul(&q_prk3_eval_zeta.mul(alpha_pow_7)));

    #[cfg(feature = "shuffle")]
    {
        let alpha_pow_10 = alpha_pow_7.mul(alpha.mul(alpha).mul(alpha));
        let alpha_pow_11 = alpha_pow_10.mul(alpha);
        let alpha_pow_12 = alpha_pow_11.mul(alpha);
        let alpha_pow_13 = alpha_pow_12.mul(alpha);

        let sel_00 = (one - w_sel_polys_eval_zeta[0]) * (one - w_sel_polys_eval_zeta[1])
            + q_ecc_poly_eval_zeta
            - one;
        let sel_01 = *w_sel_polys_eval_zeta[0] * (one - w_sel_polys_eval_zeta[1]);
        let sel_10 = (one - w_sel_polys_eval_zeta[0]) * w_sel_polys_eval_zeta[1];
        let sel_11 = *w_sel_polys_eval_zeta[0] * w_sel_polys_eval_zeta[1];
        let q_pk_x_00 = &q_shuffle_public_key_polys_or_comms[0];
        let q_pk_x_01 = &q_shuffle_public_key_polys_or_comms[1];
        let q_pk_x_10 = &q_shuffle_public_key_polys_or_comms[2];
        let q_pk_x_11 = &q_shuffle_public_key_polys_or_comms[3];
        let q_pk_y_00 = &q_shuffle_public_key_polys_or_comms[4];
        let q_pk_y_01 = &q_shuffle_public_key_polys_or_comms[5];
        let q_pk_y_10 = &q_shuffle_public_key_polys_or_comms[6];
        let q_pk_y_11 = &q_shuffle_public_key_polys_or_comms[7];
        let q_pk_dxy_00 = &q_shuffle_public_key_polys_or_comms[8];
        let q_pk_dxy_01 = &q_shuffle_public_key_polys_or_comms[9];
        let q_pk_dxy_10 = &q_shuffle_public_key_polys_or_comms[10];
        let q_pk_dxy_11 = &q_shuffle_public_key_polys_or_comms[11];
        let q_g_x_00 = &q_shuffle_generator_polys_or_comms[0];
        let q_g_x_01 = &q_shuffle_generator_polys_or_comms[1];
        let q_g_x_10 = &q_shuffle_generator_polys_or_comms[2];
        let q_g_x_11 = &q_shuffle_generator_polys_or_comms[3];
        let q_g_y_00 = &q_shuffle_generator_polys_or_comms[4];
        let q_g_y_01 = &q_shuffle_generator_polys_or_comms[5];
        let q_g_y_10 = &q_shuffle_generator_polys_or_comms[6];
        let q_g_y_11 = &q_shuffle_generator_polys_or_comms[7];
        let q_g_dxy_00 = &q_shuffle_generator_polys_or_comms[8];
        let q_g_dxy_01 = &q_shuffle_generator_polys_or_comms[9];
        let q_g_dxy_10 = &q_shuffle_generator_polys_or_comms[10];
        let q_g_dxy_11 = &q_shuffle_generator_polys_or_comms[11];

        // 6. +  alpha^10 *
        // (((1 - w_sel[0]) * (1 - w_sel[1]) + q_{ecc} - 1) * (- w_sel[2] * w[0] * q_{pk_y_00} - w[1] * q_{pk_x_00} + w[0] * w[1] * w_next[0] *  q_{pk_dxy_00}) +
        // w_sel[0] *  (1 - w_sel[1]) * (- w_sel[2] * w[0] * q_{pk_y_01} - w[1] * q_{pk_x_01} + w[0] * w[1] * w_next[0] *  q_{pk_dxy_01}) +
        // (1 - w_sel[0]) *  w_sel[1] * (- w_sel[2] * w[0] * q_{pk_y_10} - w[1] * q_{pk_x_10} + w[0] * w[1] * w_next[0] *  q_{pk_dxy_10}) +
        // w_sel[0] *  w_sel[1] * (- w_sel[2] * w[0] * q_{pk_y_11} - w[1] * q_{pk_x_11} + w[0] * w[1] * w_next[0] *  q_{pk_dxy_11}))
        let tmp = q_pk_dxy_00
            .mul(
                &w_polys_eval_zeta[0]
                    .mul(w_polys_eval_zeta[1])
                    .mul(w_polys_eval_zeta_omega[0]),
            )
            .sub(&q_pk_y_00.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[0])))
            .sub(&q_pk_x_00.mul(&w_polys_eval_zeta[1]))
            .mul(&sel_00)
            .add(
                &q_pk_dxy_01
                    .mul(
                        &w_polys_eval_zeta[0]
                            .mul(w_polys_eval_zeta[1])
                            .mul(w_polys_eval_zeta_omega[0]),
                    )
                    .sub(&q_pk_y_01.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[0])))
                    .sub(&q_pk_x_01.mul(&w_polys_eval_zeta[1]))
                    .mul(&sel_01),
            )
            .add(
                &q_pk_dxy_10
                    .mul(
                        &w_polys_eval_zeta[0]
                            .mul(w_polys_eval_zeta[1])
                            .mul(w_polys_eval_zeta_omega[0]),
                    )
                    .sub(&q_pk_y_10.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[0])))
                    .sub(&q_pk_x_10.mul(&w_polys_eval_zeta[1]))
                    .mul(&sel_10),
            )
            .add(
                &q_pk_dxy_11
                    .mul(
                        &w_polys_eval_zeta[0]
                            .mul(w_polys_eval_zeta[1])
                            .mul(w_polys_eval_zeta_omega[0]),
                    )
                    .sub(&q_pk_y_11.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[0])))
                    .sub(&q_pk_x_11.mul(&w_polys_eval_zeta[1]))
                    .mul(&sel_11),
            );

        l.add_assign(&tmp.mul(&alpha_pow_10));

        // 7. +  alpha^11 *
        // ((1 - w_sel[0]) * (1 - w_sel[1]) + q_{ecc} - 1) * (a * w[0] * q_{pk_x_00} - w_sel[2] * w[1] * q_{pk_y_00} - w[0] * w[1] * w_next[1] *  q_{pk_dxy_00}) *
        // w_sel[0] *  (1 - w_sel[1]) * (a * w[0] * q_{pk_x_01} - w_sel[2] * w[1] * q_{pk_y_01} - w[0] * w[1] * w_next[1] *  q_{pk_dxy_01})
        // (1 - w_sel[0]) *  w_sel[1] * (a * w[0] * q_{pk_x_10} - w_sel[2] * w[1] * q_{pk_y_10} - w[0] * w[1] * w_next[1] *  q_{pk_dxy_10})
        // w_sel[0] *  w_sel[1] * (a * w[0] * q_{pk_x_11} - w_sel[2] * w[1] * q_{pk_y_11} - w[0] * w[1] * w_next[1] *  q_{pk_dxy_11})
        let tmp = q_pk_dxy_00
            .mul(
                &-w_polys_eval_zeta[0]
                    .mul(w_polys_eval_zeta[1])
                    .mul(w_polys_eval_zeta_omega[1]),
            )
            .add(&q_pk_x_00.mul(&w_polys_eval_zeta[0].mul(edwards_a)))
            .sub(&q_pk_y_00.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[1])))
            .mul(&sel_00)
            .add(
                &q_pk_dxy_01
                    .mul(
                        &-w_polys_eval_zeta[0]
                            .mul(w_polys_eval_zeta[1])
                            .mul(w_polys_eval_zeta_omega[1]),
                    )
                    .add(&q_pk_x_01.mul(&w_polys_eval_zeta[0].mul(edwards_a)))
                    .sub(&q_pk_y_01.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[1])))
                    .mul(&sel_01),
            )
            .add(
                &q_pk_dxy_10
                    .mul(
                        &-w_polys_eval_zeta[0]
                            .mul(w_polys_eval_zeta[1])
                            .mul(w_polys_eval_zeta_omega[1]),
                    )
                    .add(&q_pk_x_10.mul(&w_polys_eval_zeta[0].mul(edwards_a)))
                    .sub(&q_pk_y_10.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[1])))
                    .mul(&sel_10),
            )
            .add(
                &q_pk_dxy_11
                    .mul(
                        &-w_polys_eval_zeta[0]
                            .mul(w_polys_eval_zeta[1])
                            .mul(w_polys_eval_zeta_omega[1]),
                    )
                    .add(&q_pk_x_11.mul(&w_polys_eval_zeta[0].mul(edwards_a)))
                    .sub(&q_pk_y_11.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[1])))
                    .mul(&sel_11),
            );

        l.add_assign(&tmp.mul(&alpha_pow_11));

        // 8. +  alpha^12 *
        // ((1 - w_sel[0]) * (1 - w_sel[1]) + q_{ecc} - 1) * (- w_sel[2] * w[2] * q_{g_y_00} - w[3] * q_{g_x_00} + w[2] * w[3] * w_next[2] *  q_{g_dxy_00}) *
        // w_sel[0] *  (1 - w_sel[1]) * (- w_sel[2] * w[2] * q_{g_y_01} - w[3] * q_{g_x_01} + w[2] * w[3] * w_next[2] *  q_{g_dxy_01})
        // (1 - w_sel[0]) *  w_sel[1] * (- w_sel[2] * w[2] * q_{g_y_10} - w[3] * q_{g_x_10} + w[2] * w[3] * w_next[2] *  q_{g_dxy_10})
        // w_sel[0] *  w_sel[1] * (- w_sel[2] * w[2] * q_{g_y_11} - w[3] * q_{g_x_11} + w[2] * w[3] * w_next[2] *  q_{g_dxy_11})
        let tmp = q_g_dxy_00
            .mul(
                &w_polys_eval_zeta[2]
                    .mul(w_polys_eval_zeta[3])
                    .mul(w_polys_eval_zeta_omega[2]),
            )
            .sub(&q_g_y_00.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[2])))
            .sub(&q_g_x_00.mul(&w_polys_eval_zeta[3]))
            .mul(&sel_00)
            .add(
                &q_g_dxy_01
                    .mul(
                        &w_polys_eval_zeta[2]
                            .mul(w_polys_eval_zeta[3])
                            .mul(w_polys_eval_zeta_omega[2]),
                    )
                    .sub(&q_g_y_01.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[2])))
                    .sub(&q_g_x_01.mul(&w_polys_eval_zeta[3]))
                    .mul(&sel_01),
            )
            .add(
                &q_g_dxy_10
                    .mul(
                        &w_polys_eval_zeta[2]
                            .mul(w_polys_eval_zeta[3])
                            .mul(w_polys_eval_zeta_omega[2]),
                    )
                    .sub(&q_g_y_10.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[2])))
                    .sub(&q_g_x_10.mul(&w_polys_eval_zeta[3]))
                    .mul(&sel_10),
            )
            .add(
                &q_g_dxy_11
                    .mul(
                        &w_polys_eval_zeta[2]
                            .mul(w_polys_eval_zeta[3])
                            .mul(w_polys_eval_zeta_omega[2]),
                    )
                    .sub(&q_g_y_11.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[2])))
                    .sub(&q_g_x_11.mul(&w_polys_eval_zeta[3]))
                    .mul(&sel_11),
            );

        l.add_assign(&tmp.mul(&alpha_pow_12));

        // 9. +  alpha^13 *
        // ((1 - w_sel[0]) * (1 - w_sel[1]) + q_{ecc} - 1) * (a * w[2] * q_{g_x_00} - w_sel[2] * w[3] * q_{g_y_00} + w[2] * w[3] * w[4] *  q_{pk_gxy_00}) *
        // w_sel[0] *  (1 - w_sel[1]) * (a * w[2] * q_{g_x_01} - w_sel[2] * w[3] * q_{g_y_01} + w[2] * w[3] * w[4] *  q_{pk_gxy_01})
        // (1 - w_sel[0]) *  w_sel[1] * (a * w[2] * q_{g_x_10} - w_sel[2] * w[3] * q_{g_y_10} + w[2] * w[3] * w[4] *  q_{pk_gxy_10})
        // w_sel[0] *  w_sel[1] * (a * w[2] * q_{g_x_11} - w_sel[2] * w[3] * q_{g_y_11} + w[2] * w[3] * w[4] *  q_{pk_gxy_11})
        let tmp = q_g_dxy_00
            .mul(
                &-w_polys_eval_zeta[2]
                    .mul(w_polys_eval_zeta[3])
                    .mul(w_polys_eval_zeta[4]),
            )
            .add(&q_g_x_00.mul(&w_polys_eval_zeta[2].mul(edwards_a)))
            .sub(&q_g_y_00.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[3])))
            .mul(&sel_00)
            .add(
                &q_g_dxy_01
                    .mul(
                        &-w_polys_eval_zeta[2]
                            .mul(w_polys_eval_zeta[3])
                            .mul(w_polys_eval_zeta[4]),
                    )
                    .add(&q_g_x_01.mul(&w_polys_eval_zeta[2].mul(edwards_a)))
                    .sub(&q_g_y_01.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[3])))
                    .mul(&sel_01),
            )
            .add(
                &q_g_dxy_10
                    .mul(
                        &-w_polys_eval_zeta[2]
                            .mul(w_polys_eval_zeta[3])
                            .mul(w_polys_eval_zeta[4]),
                    )
                    .add(&q_g_x_10.mul(&w_polys_eval_zeta[2].mul(edwards_a)))
                    .sub(&q_g_y_10.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[3])))
                    .mul(&sel_10),
            )
            .add(
                &q_g_dxy_11
                    .mul(
                        &-w_polys_eval_zeta[2]
                            .mul(w_polys_eval_zeta[3])
                            .mul(w_polys_eval_zeta[4]),
                    )
                    .add(&q_g_x_11.mul(&w_polys_eval_zeta[2].mul(edwards_a)))
                    .sub(&q_g_y_11.mul(&w_sel_polys_eval_zeta[2].mul(w_polys_eval_zeta[3])))
                    .mul(&sel_11),
            );

        l.add_assign(&tmp.mul(&alpha_pow_13));
    }

    let factor = zeta.pow(&[n_t_polys as u64]);
    let mut exponent = z_h_eval_zeta.mul(factor);
    let mut t_poly_combined = t_polys_or_comms[0].clone().mul(&z_h_eval_zeta);
    for t_poly in t_polys_or_comms.iter().skip(1) {
        t_poly_combined.add_assign(&t_poly.mul(&exponent));
        exponent.mul_assign(&factor);
    }
    l.sub_assign(&t_poly_combined);
    l
}

/// compute the scalar factor of z(X) in the r poly.
/// prod(fi(\zeta) + \beta * k_i * \zeta + \gamma) * \alpha
///       + (\zeta^n - 1) / (\zeta-1) * \alpha^2
fn compute_z_scalar_in_r<F: PrimeField>(
    w_polys_eval_zeta: &[&F],
    k: &[F],
    challenges: &PlonkChallenges<F>,
    first_lagrange_eval_zeta: &F,
) -> F {
    let n_wires_per_gate = w_polys_eval_zeta.len();
    let (beta, gamma) = challenges.get_beta_gamma().unwrap();
    let alpha = challenges.get_alpha().unwrap();
    let alpha_square = alpha.mul(alpha);
    let zeta = challenges.get_zeta().unwrap();

    // 1. alpha * prod_{i=1..n_wires_per_gate}(fi(\zeta) + \beta * k_i * \zeta + \gamma)
    let beta_zeta = beta.mul(zeta);
    let mut z_scalar = *alpha;
    for i in 0..n_wires_per_gate {
        let tmp = w_polys_eval_zeta[i].add(&k[i].mul(&beta_zeta)).add(gamma);
        z_scalar.mul_assign(&tmp);
    }

    // 2. alpha^2 * (beta^n - 1) / (beta - 1)
    z_scalar.add_assign(&first_lagrange_eval_zeta.mul(alpha_square));
    z_scalar
}

/// Compute the r polynomial.
pub(super) fn r_poly<PCS: PolyComScheme, CS: ConstraintSystem<PCS::Field>>(
    prover_params: &PlonkProverParams<PCS>,
    z: &FpPolynomial<PCS::Field>,
    w_polys_eval_zeta: &[&PCS::Field],
    #[cfg(feature = "shuffle")] w_polys_eval_zeta_omega: &[&PCS::Field],
    s_polys_eval_zeta: &[&PCS::Field],
    q_prk3_eval_zeta: &PCS::Field,
    z_eval_zeta_omega: &PCS::Field,
    #[cfg(feature = "shuffle")] q_ecc_poly_eval_zeta: &PCS::Field,
    #[cfg(feature = "shuffle")] w_sel_polys_eval_zeta: &[&PCS::Field],
    challenges: &PlonkChallenges<PCS::Field>,
    t_polys: &[FpPolynomial<PCS::Field>],
    first_lagrange_eval_zeta: &PCS::Field,
    z_h_eval_zeta: &PCS::Field,
    #[cfg(feature = "shuffle")] edwards_a: &PCS::Field,
    n_t_polys: usize,
) -> FpPolynomial<PCS::Field> {
    let w = CS::eval_selector_multipliers(w_polys_eval_zeta).unwrap(); // safe unwrap
    r_poly_or_comm::<PCS::Field, FpPolynomial<PCS::Field>>(
        &w,
        &prover_params.q_polys,
        &prover_params.qb_poly,
        &prover_params.q_prk_polys[0],
        &prover_params.q_prk_polys[1],
        #[cfg(feature = "shuffle")]
        &prover_params.q_shuffle_generator_polys,
        #[cfg(feature = "shuffle")]
        &prover_params.q_shuffle_public_key_polys,
        #[cfg(feature = "shuffle")]
        q_ecc_poly_eval_zeta,
        #[cfg(feature = "shuffle")]
        w_sel_polys_eval_zeta,
        &prover_params.verifier_params.k,
        #[cfg(feature = "shuffle")]
        edwards_a,
        &prover_params.s_polys[CS::n_wires_per_gate() - 1],
        z,
        w_polys_eval_zeta,
        #[cfg(feature = "shuffle")]
        w_polys_eval_zeta_omega,
        s_polys_eval_zeta,
        q_prk3_eval_zeta,
        z_eval_zeta_omega,
        challenges,
        t_polys,
        first_lagrange_eval_zeta,
        z_h_eval_zeta,
        n_t_polys,
    )
}

/// Commit the r commitment.
pub(super) fn r_commitment<PCS: PolyComScheme, CS: ConstraintSystem<PCS::Field>>(
    verifier_params: &PlonkVerifierParams<PCS>,
    cm_z: &PCS::Commitment,
    w_polys_eval_zeta: &[&PCS::Field],
    #[cfg(feature = "shuffle")] w_sel_polys_eval_zeta: &[&PCS::Field],
    s_polys_eval_zeta: &[&PCS::Field],
    q_prk3_eval_zeta: &PCS::Field,
    #[cfg(feature = "shuffle")] q_ecc_poly_eval_zeta: &PCS::Field,
    #[cfg(feature = "shuffle")] w_polys_eval_zeta_omega: &[&PCS::Field],
    z_eval_zeta_omega: &PCS::Field,
    challenges: &PlonkChallenges<PCS::Field>,
    t_polys: &[PCS::Commitment],
    first_lagrange_eval_zeta: &PCS::Field,
    z_h_eval_zeta: &PCS::Field,
    n_t_polys: usize,
) -> PCS::Commitment {
    let w = CS::eval_selector_multipliers(w_polys_eval_zeta).unwrap(); // safe unwrap
    r_poly_or_comm::<PCS::Field, PCS::Commitment>(
        &w,
        &verifier_params.cm_q_vec,
        &verifier_params.cm_qb,
        &verifier_params.cm_prk_vec[0],
        &verifier_params.cm_prk_vec[1],
        #[cfg(feature = "shuffle")]
        &verifier_params.cm_shuffle_generator_vec,
        #[cfg(feature = "shuffle")]
        &verifier_params.cm_shuffle_public_key_vec,
        #[cfg(feature = "shuffle")]
        q_ecc_poly_eval_zeta,
        #[cfg(feature = "shuffle")]
        w_sel_polys_eval_zeta,
        &verifier_params.k,
        #[cfg(feature = "shuffle")]
        &verifier_params.edwards_a,
        &verifier_params.cm_s_vec[CS::n_wires_per_gate() - 1],
        cm_z,
        w_polys_eval_zeta,
        #[cfg(feature = "shuffle")]
        w_polys_eval_zeta_omega,
        s_polys_eval_zeta,
        q_prk3_eval_zeta,
        z_eval_zeta_omega,
        challenges,
        t_polys,
        first_lagrange_eval_zeta,
        z_h_eval_zeta,
        n_t_polys,
    )
}

/// Compute sum_{i=1}^\ell w_i L_j(X), where j is the constraint
/// index for the i-th public value. L_j(X) = (X^n-1) / (X - \omega^j) is
/// the j-th lagrange base (zero for every X = \omega^i, except when i == j)
pub(super) fn eval_pi_poly<PCS: PolyComScheme>(
    verifier_params: &PlonkVerifierParams<PCS>,
    public_inputs: &[PCS::Field],
    z_h_eval_zeta: &PCS::Field,
    eval_point: &PCS::Field,
    root: &PCS::Field,
) -> PCS::Field {
    let mut eval = PCS::Field::zero();
    let mut denominators = Vec::new();

    for constraint_index in verifier_params.public_vars_constraint_indices.iter() {
        // X - \omega^j j-th Lagrange denominator
        let root_to_j = root.pow(&[*constraint_index as u64]);
        let denominator = eval_point.sub(&root_to_j);
        denominators.push(denominator);
    }

    batch_inversion(&mut denominators);

    for (public_value, (lagrange_constant, denominator_inv)) in public_inputs.iter().zip(
        verifier_params
            .lagrange_constants
            .iter()
            .zip(denominators.iter()),
    ) {
        let lagrange_i = lagrange_constant.mul(denominator_inv);
        eval.add_assign(&lagrange_i.mul(public_value));
    }

    eval.mul(z_h_eval_zeta)
}

/// Compute constant c_j such that 1 = c_j * prod_{i != j} (\omega^j - \omega^i).
/// In such case, j-th lagrange base can be represented
/// by L_j(X) = c_j (X^n-1) / (X- \omega^j)
pub(super) fn compute_lagrange_constant<F: PrimeField>(group: &[F], base_index: usize) -> F {
    let mut constant_inv = F::one();
    for (i, elem) in group.iter().enumerate() {
        if i == base_index {
            continue;
        }
        constant_inv.mul_assign(&group[base_index].sub(elem));
    }
    constant_inv.inverse().unwrap()
}

/// Evaluate the r polynomial at point \zeta.
pub(super) fn r_eval_zeta<PCS: PolyComScheme>(
    proof: &PlonkProof<PCS>,
    challenges: &PlonkChallenges<PCS::Field>,
    pi_eval_zeta: &PCS::Field,
    first_lagrange_eval_zeta: &PCS::Field,
    anemoi_generator: PCS::Field,
    anemoi_generator_inv: PCS::Field,
) -> PCS::Field {
    let alpha = challenges.get_alpha().unwrap();
    let alpha_pow_2 = alpha.mul(alpha);
    let alpha_pow_3 = alpha_pow_2.mul(alpha);
    let alpha_pow_4 = alpha_pow_3.mul(alpha);
    let alpha_pow_5 = alpha_pow_4.mul(alpha);
    let alpha_pow_6 = alpha_pow_5.mul(alpha);
    let alpha_pow_7 = alpha_pow_6.mul(alpha);
    let alpha_pow_8 = alpha_pow_7.mul(alpha);
    let alpha_pow_9 = alpha_pow_8.mul(alpha);

    let (beta, gamma) = challenges.get_beta_gamma().unwrap();

    let term0 = pi_eval_zeta;
    let mut term1 = alpha.mul(&proof.z_eval_zeta_omega);
    let n_wires_per_gate = &proof.w_polys_eval_zeta.len();
    for i in 0..n_wires_per_gate - 1 {
        let b = proof.w_polys_eval_zeta[i]
            .add(&beta.mul(&proof.s_polys_eval_zeta[i]))
            .add(gamma);
        term1.mul_assign(&b);
    }
    term1.mul_assign(&proof.w_polys_eval_zeta[n_wires_per_gate - 1].add(gamma));

    let term2 = first_lagrange_eval_zeta.mul(alpha_pow_2);

    let w3_w0 = proof.w_polys_eval_zeta[3] + proof.w_polys_eval_zeta[0];
    let w2_w1 = proof.w_polys_eval_zeta[2] + proof.w_polys_eval_zeta[1];

    let w3_2w0 = w3_w0 + proof.w_polys_eval_zeta[0];
    let w2_2w1 = w2_w1 + proof.w_polys_eval_zeta[1];

    let five = &[5u64];
    let tmp = w3_w0 + &(anemoi_generator * &w2_w1) + &proof.prk_3_poly_eval_zeta;
    let term3 = alpha_pow_6.mul(&proof.prk_3_poly_eval_zeta).mul(
        (tmp - &proof.w_polys_eval_zeta_omega[2]).pow(five) + anemoi_generator * &tmp.square()
            - &(w3_2w0 + &(anemoi_generator * &w2_2w1)),
    );
    let term5 = alpha_pow_8.mul(&proof.prk_3_poly_eval_zeta).mul(
        (tmp - &proof.w_polys_eval_zeta_omega[2]).pow(five)
            + anemoi_generator * &proof.w_polys_eval_zeta_omega[2].square()
            + anemoi_generator_inv
            - &proof.w_polys_eval_zeta_omega[0],
    );

    let anemoi_generator_square_plus_one = anemoi_generator.square().add(PCS::Field::one());
    let tmp = anemoi_generator * &w3_w0
        + &(anemoi_generator_square_plus_one * &w2_w1)
        + &proof.prk_4_poly_eval_zeta;
    let term4 = alpha_pow_7.mul(&proof.prk_3_poly_eval_zeta).mul(
        (tmp - &proof.w_polys_eval_zeta[4]).pow(five) + anemoi_generator * &tmp.square()
            - &(anemoi_generator * &w3_2w0 + &(anemoi_generator_square_plus_one * &w2_2w1)),
    );
    let term6 = alpha_pow_9.mul(&proof.prk_3_poly_eval_zeta).mul(
        (tmp - &proof.w_polys_eval_zeta[4]).pow(five)
            + anemoi_generator * &proof.w_polys_eval_zeta[4].square()
            + anemoi_generator_inv
            - &proof.w_polys_eval_zeta_omega[1],
    );

    #[cfg(feature = "shuffle")]
    let (term7, term8, term9, term10) = {
        let one = PCS::Field::ONE;
        let alpha_pow_10 = alpha_pow_9.mul(alpha);
        let alpha_pow_11 = alpha_pow_10.mul(alpha);
        let alpha_pow_12 = alpha_pow_11.mul(alpha);
        let alpha_pow_13 = alpha_pow_12.mul(alpha);
        let alpha_pow_14 = alpha_pow_13.mul(alpha);
        let alpha_pow_15 = alpha_pow_14.mul(alpha);
        let alpha_pow_16 = alpha_pow_15.mul(alpha);

        let sel_00 = one
            .sub(&proof.w_sel_polys_eval_zeta[0])
            .mul(one.sub(&proof.w_sel_polys_eval_zeta[1]))
            .add(&proof.q_ecc_poly_eval_zeta)
            .sub(&one);
        let sel_01 = proof.w_sel_polys_eval_zeta[0].mul(one.sub(&proof.w_sel_polys_eval_zeta[1]));
        let sel_10 = one
            .sub(&proof.w_sel_polys_eval_zeta[0])
            .mul(&proof.w_sel_polys_eval_zeta[1]);
        let sel_11 = proof.w_sel_polys_eval_zeta[0].mul(&proof.w_sel_polys_eval_zeta[1]);
        let term7 = proof.w_sel_polys_eval_zeta[2]
            .mul(
                alpha_pow_10
                    .mul(&proof.w_polys_eval_zeta_omega[0])
                    .add(alpha_pow_11.mul(&proof.w_polys_eval_zeta_omega[1]))
                    .add(alpha_pow_12.mul(&proof.w_polys_eval_zeta_omega[2]))
                    .add(alpha_pow_13.mul(&proof.w_polys_eval_zeta[4])),
            )
            .mul(sel_00.add(&sel_01).add(&sel_10).add(&sel_11));

        let term8 = alpha_pow_14.mul(
            proof
                .q_ecc_poly_eval_zeta
                .mul(&proof.w_sel_polys_eval_zeta[0])
                .mul(one.sub(&proof.w_sel_polys_eval_zeta[0]))
                .add(
                    one.sub(&proof.q_ecc_poly_eval_zeta)
                        .mul(&proof.w_sel_polys_eval_zeta[0]),
                ),
        );
        let term9 = alpha_pow_15.mul(
            proof
                .q_ecc_poly_eval_zeta
                .mul(&proof.w_sel_polys_eval_zeta[1])
                .mul(one.sub(&proof.w_sel_polys_eval_zeta[1]))
                .add(
                    one.sub(&proof.q_ecc_poly_eval_zeta)
                        .mul(&proof.w_sel_polys_eval_zeta[1]),
                ),
        );
        let term10 = alpha_pow_16
            .mul(proof.q_ecc_poly_eval_zeta)
            .mul(one.sub(&proof.w_sel_polys_eval_zeta[2]))
            .mul(one.add(&proof.w_sel_polys_eval_zeta[2]));

        (term7, term8, term9, term10)
    };

    let term1_plus_term2 = term1.add(&term2);
    let res = term1_plus_term2
        .sub(term0)
        .add(term3)
        .add(term4)
        .add(term5)
        .add(term6);

    #[cfg(feature = "shuffle")]
    let res = { res.sub(term7).sub(term8).sub(term9).sub(term10) };

    res
}

/// Split the t polynomial into `n_wires_per_gate` degree-`n` polynomials and commit.
pub(crate) fn split_t_and_commit<R: CryptoRng + RngCore, PCS: PolyComScheme>(
    prng: &mut R,
    pcs: &PCS,
    lagrange_pcs: Option<&PCS>,
    t: &FpPolynomial<PCS::Field>,
    n_wires_per_gate: usize,
    n: usize,
) -> Result<(Vec<PCS::Commitment>, Vec<FpPolynomial<PCS::Field>>), UzkgeError> {
    let mut cm_t_vec = vec![];
    let mut t_polys = vec![];
    let coefs_len = t.get_coefs_ref().len();

    let zero = PCS::Field::zero();
    let mut prev_coef = zero;

    for i in 0..n_wires_per_gate {
        let coefs_start = i * n;
        let coefs_end = if i == n_wires_per_gate - 1 {
            coefs_len
        } else {
            (i + 1) * n
        };

        let mut coefs = if coefs_start < coefs_len {
            t.get_coefs_ref()[coefs_start..min(coefs_len, coefs_end)].to_vec()
        } else {
            vec![]
        };

        let rand = PCS::Field::rand(prng);
        if i != n_wires_per_gate - 1 {
            coefs.resize(n + 1, zero);
            coefs[n].add_assign(&rand);
            coefs[0].sub_assign(&prev_coef);
        } else {
            if coefs.len() == 0 {
                coefs = vec![prev_coef.neg()];
            } else {
                coefs[0].sub_assign(&prev_coef);
            }
        }
        prev_coef = rand;

        let (cm_t, t_poly) = if let Some(lagrange_pcs) = lagrange_pcs {
            let degree = coefs.len();
            let mut max_power_of_2 = degree;
            for i in (0..=degree).rev() {
                if (i & (i - 1)) == 0 {
                    max_power_of_2 = i;
                    break;
                }
            }

            let mut blinds = vec![];
            for i in &coefs[max_power_of_2..] {
                blinds.push(i.neg());
            }

            let mut new_coefs = coefs[..max_power_of_2].to_vec();
            for (i, v) in blinds.iter().enumerate() {
                new_coefs[i] = new_coefs[i] - v;
            }

            let sub_q = FpPolynomial::from_coefs(new_coefs);
            let q_eval = FpPolynomial::fft(&sub_q, max_power_of_2).ok_or(UzkgeError::FFTError)?;
            let q_eval = FpPolynomial::from_coefs(q_eval);

            let cm = lagrange_pcs
                .commit(&q_eval)
                .map_err(|_| UzkgeError::CommitmentError)?;
            let cm_t = pcs.apply_blind_factors(&cm, &blinds, max_power_of_2);
            (cm_t, FpPolynomial::from_coefs(coefs))
        } else {
            let t_poly = FpPolynomial::from_coefs(coefs);
            let cm_t = pcs
                .commit(&t_poly)
                .map_err(|_| UzkgeError::CommitmentError)?;
            (cm_t, t_poly)
        };

        cm_t_vec.push(cm_t);
        t_polys.push(t_poly);
    }

    Ok((cm_t_vec, t_polys))
}

/// for a evaluation domain H, when x = 1, L_1(x) = (x^n-1) / (x-1) != 0,
/// when x = a and a \in H different from 1, L_1(x) = 0.
pub(super) fn first_lagrange_poly<PCS: PolyComScheme>(
    challenges: &PlonkChallenges<PCS::Field>,
    group_order: u64,
) -> (PCS::Field, PCS::Field) {
    let zeta = challenges.get_zeta().unwrap();
    let one = PCS::Field::one();
    let zeta_n = zeta.pow(&[group_order]);
    let z_h_eval_zeta = zeta_n.sub(&one);
    let zeta_minus_one = zeta.sub(&one);
    let l1_eval_zeta = z_h_eval_zeta.mul(zeta_minus_one.inverse().unwrap());
    (z_h_eval_zeta, l1_eval_zeta)
}

#[cfg(test)]
mod test {
    use ark_bn254::Bn254;
    use ark_ff::{One, Zero};
    use ark_std::{ops::*, rand::SeedableRng};
    use rand_chacha::ChaChaRng;

    use crate::{
        plonk::{
            constraint_system::TurboCS,
            helpers::{z_poly, PlonkChallenges},
            indexer::indexer,
        },
        poly_commit::kzg_poly_commitment::{KZGCommitmentScheme, KZGCommitmentSchemeBN254},
    };

    #[test]
    fn test_z_polynomial() {
        type F = ark_bn254::Fr;
        let mut cs = TurboCS::new();
        let zero = F::zero();
        let one = F::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let four = three.add(&one);
        let five = four.add(&one);
        let six = five.add(&one);
        let seven = six.add(&one);

        let witness = [one, three, five, four, two, two, seven, six];
        cs.add_variables(&witness);

        cs.insert_add_gate(0 + 2, 4 + 2, 1 + 2);
        cs.insert_add_gate(1 + 2, 4 + 2, 2 + 2);
        cs.insert_add_gate(2 + 2, 4 + 2, 6 + 2);
        cs.insert_add_gate(3 + 2, 5 + 2, 7 + 2);
        cs.pad();

        let mut prng = ChaChaRng::from_entropy();
        let pcs = KZGCommitmentScheme::<Bn254>::new(20, &mut prng);
        let params = indexer(&cs, &pcs).unwrap();

        let mut challenges = PlonkChallenges::<F>::new();
        challenges.insert_beta_gamma(one, zero).unwrap();
        let q = z_poly::<KZGCommitmentSchemeBN254, TurboCS<F>>(&params, &witness[..], &challenges);

        let q0 = q.coefs[0];
        assert_eq!(q0, one);
    }
}
