use ark_bn254::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_poly::EvaluationDomain;
use ark_serialize::CanonicalSerialize;
use ark_std::{
    ops::*,
    rand::{CryptoRng, RngCore, SeedableRng},
};
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};

use crate::{
    errors::UzkgeError,
    poly_commit::{
        field_polynomial::FpPolynomial,
        kzg_poly_commitment::{KZGCommitment, KZGCommitmentSchemeBN254},
        pcs::PolyComScheme,
    },
    utils::{
        serialization::{
            ark_deserialize, ark_serialize, point_from_uncompress_be, point_to_uncompress_be,
            scalar_from_bytes_be, scalar_to_bytes_be,
        },
        shift_u8_vec, u64_limbs_from_bytes,
    },
};

use super::{constraint_system::ConstraintSystem, helpers::compute_lagrange_constant};

/// The data structure of a Plonk proof.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlonkProof<PCS: PolyComScheme> {
    /// The witness polynomial commitments.
    pub cm_w_vec: Vec<PCS::Commitment>,
    /// The witness selector polynomial commitments.
    #[cfg(feature = "shuffle")]
    pub cm_w_sel_vec: Vec<PCS::Commitment>,
    /// The split quotient polynomial commitments
    pub cm_t_vec: Vec<PCS::Commitment>,
    /// The sigma polynomial commitment.
    pub cm_z: PCS::Commitment,
    /// The opening of the third preprocessed round key polynomial at \zeta.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub prk_3_poly_eval_zeta: PCS::Field,
    /// The opening of the fourth preprocessed round key polynomial at \zeta.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub prk_4_poly_eval_zeta: PCS::Field,
    /// The openings of witness polynomials at \zeta.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub w_polys_eval_zeta: Vec<PCS::Field>,
    /// The openings of witness polynomials (first three) at \zeta * \omega.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub w_polys_eval_zeta_omega: Vec<PCS::Field>,
    /// The opening of z(X) at point \zeta * \omega.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub z_eval_zeta_omega: PCS::Field,
    /// The openings of permutation polynomials at \zeta.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub s_polys_eval_zeta: Vec<PCS::Field>,
    /// The opening of q_{ecc}(X) at point \zeta .
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    #[cfg(feature = "shuffle")]
    pub q_ecc_poly_eval_zeta: PCS::Field,
    /// The opening of the witness selector polynomial at point \zeta .
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    #[cfg(feature = "shuffle")]
    pub w_sel_polys_eval_zeta: Vec<PCS::Field>,
    /// The commitment for the first witness polynomial, for \zeta.
    pub opening_witness_zeta: PCS::Commitment,
    /// The commitment for the second witness polynomial, for \zeta\omega.
    pub opening_witness_zeta_omega: PCS::Commitment,
}

/// Plonk prover parameters.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PlonkProverParams<PCS: PolyComScheme> {
    /// The polynomials of the selectors.
    pub q_polys: Vec<FpPolynomial<PCS::Field>>,
    /// The polynomials of perm1, perm2, ..., perm_{n_wires_per_gate}.
    pub s_polys: Vec<FpPolynomial<PCS::Field>>,
    /// The polynomial for boolean constraints.
    pub qb_poly: FpPolynomial<PCS::Field>,
    /// The four polynomials for the Anemoi/Jive constraints.
    pub q_prk_polys: Vec<FpPolynomial<PCS::Field>>,
    /// The polynomial for ecc constraints.
    #[cfg(feature = "shuffle")]
    pub q_ecc_poly: FpPolynomial<PCS::Field>,
    /// The generator polynomials for the shuffle constraints.
    #[cfg(feature = "shuffle")]
    pub q_shuffle_generator_polys: Vec<FpPolynomial<PCS::Field>>,
    /// The public key polynomials for the shuffle constraints.
    #[cfg(feature = "shuffle")]
    pub q_shuffle_public_key_polys: Vec<FpPolynomial<PCS::Field>>,
    /// The permutation for copy constraints.
    pub permutation: Vec<usize>,
    /// The Plonk verifier parameters.
    pub verifier_params: PlonkVerifierParams<PCS>,
    /// The elements of the group.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub group: Vec<PCS::Field>,
    /// The evaluation domain for computing the quotient polynomial.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub coset_quotient: Vec<PCS::Field>,
    /// First lagrange basis.
    pub l1_coefs: FpPolynomial<PCS::Field>,
    /// The l1's FFT of the polynomial of unity root set.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub l1_coset_evals: Vec<PCS::Field>,
    /// Initialize [one.neg, zero, zero, ... zero, one] polynomial.
    pub z_h_coefs: FpPolynomial<PCS::Field>,
    /// The z_h's FFT of the polynomial of unity root set.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub z_h_inv_coset_evals: Vec<PCS::Field>,
    /// The selector polynomials' FFT of the polynomial of unity root set.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub q_coset_evals: Vec<Vec<PCS::Field>>,
    /// The permutation polynomials' FFT of the polynomial of unity root set.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub s_coset_evals: Vec<Vec<PCS::Field>>,
    /// The boolean constraint polynomial's FFT of the polynomial of unity root set.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub qb_coset_eval: Vec<PCS::Field>,
    /// The Anemoi/Jive polynomials' FFT of the polynomial of unity root set.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub q_prk_coset_evals: Vec<Vec<PCS::Field>>,
    /// The ecc constraint polynomial's FFT of the polynomial of unity root set.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    #[cfg(feature = "shuffle")]
    pub q_ecc_coset_eval: Vec<PCS::Field>,
    /// The shuffle generator polynomials' FFT of the polynomial of unity root set.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    #[cfg(feature = "shuffle")]
    pub q_shuffle_generator_coset_evals: Vec<Vec<PCS::Field>>,
    /// The shuffle public key polynomials' FFT of the polynomial of unity root set.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    #[cfg(feature = "shuffle")]
    pub q_shuffle_public_key_coset_evals: Vec<Vec<PCS::Field>>,
}

impl<PCS: PolyComScheme> PlonkProverParams<PCS> {
    /// Return the verifier parameters.
    pub fn get_verifier_params(self) -> PlonkVerifierParams<PCS> {
        self.verifier_params
    }

    /// Return a reference of verifier parameters.
    pub fn get_verifier_params_ref(&self) -> &PlonkVerifierParams<PCS> {
        &self.verifier_params
    }
}

/// Plonk verifier parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlonkVerifierParams<PCS: PolyComScheme> {
    /// The commitments of the selectors.
    pub cm_q_vec: Vec<PCS::Commitment>,
    /// The commitments of perm1, perm2, ..., perm_{n_wires_per_gate}.
    pub cm_s_vec: Vec<PCS::Commitment>,
    /// The commitment of the boolean selector.
    pub cm_qb: PCS::Commitment,
    /// The commitments of the preprocessed round key selectors.
    pub cm_prk_vec: Vec<PCS::Commitment>,
    /// The commitment of the ecc selector.
    #[cfg(feature = "shuffle")]
    pub cm_q_ecc: PCS::Commitment,
    /// The commitments of the shuffle generator selectors.
    #[cfg(feature = "shuffle")]
    pub cm_shuffle_generator_vec: Vec<PCS::Commitment>,
    /// The commitments of the shuffle public key selectors.
    #[cfg(feature = "shuffle")]
    pub cm_shuffle_public_key_vec: Vec<PCS::Commitment>,
    /// the Anemoi generator.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub anemoi_generator: PCS::Field,
    /// the Anemoi generator's inverse.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub anemoi_generator_inv: PCS::Field,
    /// `n_wires_per_gate` different quadratic non-residue in F_q-{0}.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub k: Vec<PCS::Field>,
    /// the paramater a of twisted edwards curve.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    #[cfg(feature = "shuffle")]
    pub edwards_a: PCS::Field,
    /// The size of constraint system.
    pub cs_size: usize,
    /// The public constrain variables indices.
    pub public_vars_constraint_indices: Vec<usize>,
    /// The constrain lagrange base by public constrain variables.
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub lagrange_constants: Vec<PCS::Field>,
}

/// Encode the permutation value, from an index to a group element.
pub fn encode_perm_to_group<F: PrimeField>(group: &[F], perm: &[usize], k: &[F]) -> Vec<F> {
    let n = group.len();
    perm.iter()
        .map(|pi| {
            for (i, ki) in k.iter().enumerate().skip(1) {
                if *pi < (i + 1) * n && *pi >= i * n {
                    return ki.mul(&group[pi % n]);
                }
            }
            group[pi % n]
        })
        .collect()
}

/// Find `n_wires_per_gate - 1` different quadratic non-residue in F_q-{0}.
pub fn choose_ks<R: CryptoRng + RngCore, F: PrimeField>(
    prng: &mut R,
    n_wires_per_gate: usize,
) -> Vec<F> {
    let mut k = vec![F::one()];

    // divide by 2 by shifting, first bit is one since F is odd prime
    let mut q_minus_1_half_le = F::MODULUS.to_bytes_le();
    shift_u8_vec(&mut q_minus_1_half_le);
    let exp = { u64_limbs_from_bytes(&q_minus_1_half_le) };

    for _ in 1..n_wires_per_gate {
        loop {
            let ki = F::rand(prng);
            if ki == F::zero() {
                continue;
            }
            if k.iter().all(|x| x != &ki) && ki.pow(&exp) != F::one() {
                k.push(ki);
                break;
            }
        }
    }
    k
}

/// Run the Plonk indexer.
/// Before invoking indexer function, the constraint system `cs` should pad the number of
/// constraints to a power of two.
pub fn indexer<PCS: PolyComScheme, CS: ConstraintSystem<PCS::Field>>(
    cs: &CS,
    pcs: &PCS,
) -> Result<PlonkProverParams<PCS>, UzkgeError> {
    indexer_with_lagrange(cs, pcs, None, None, None)
}

/// The Plonk indexer that leverages Lagrange bases
pub fn indexer_with_lagrange<PCS: PolyComScheme, CS: ConstraintSystem<PCS::Field>>(
    cs: &CS,
    pcs: &PCS,
    lagrange_pcs: Option<&PCS>,
    permutation: Option<Vec<usize>>,
    verifier_params: Option<PlonkVerifierParams<PCS>>,
) -> Result<PlonkProverParams<PCS>, UzkgeError> {
    let no_verifier = verifier_params.is_none();

    // It's okay to choose a fixed seed to generate quadratic non-residue.
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let n_wires_per_gate = CS::n_wires_per_gate();
    let n = cs.size();
    let m = cs.quot_eval_dom_size();
    let factor = m / n;
    if n * factor != m {
        return Err(UzkgeError::SetupError);
    }
    let lagrange_pcs = if lagrange_pcs.is_some() && lagrange_pcs.unwrap().max_degree() + 1 == n {
        lagrange_pcs
    } else {
        None
    };

    let domain =
        FpPolynomial::<PCS::Field>::evaluation_domain(n).ok_or(UzkgeError::GroupNotFound(n))?;
    let domain_m = FpPolynomial::<PCS::Field>::quotient_evaluation_domain(m)
        .ok_or(UzkgeError::GroupNotFound(m))?;
    let group = domain.elements().map(|v| v).collect::<Vec<_>>();
    let k = choose_ks::<_, PCS::Field>(&mut prng, n_wires_per_gate);
    let coset_quotient = domain_m
        .elements()
        .into_iter()
        .map(|x| k[1].mul(x))
        .collect();

    let commit = |evals: Vec<PCS::Field>,
                  coef_polynomial: &FpPolynomial<PCS::Field>|
     -> Result<PCS::Commitment, UzkgeError> {
        if let Some(lagrange_pcs) = lagrange_pcs {
            let eval_poly = FpPolynomial::from_coefs(evals);
            let cm = lagrange_pcs
                .commit(&eval_poly)
                .map_err(|_| UzkgeError::SetupError)?;
            Ok(cm)
        } else {
            let cm = pcs
                .commit(&coef_polynomial)
                .map_err(|_| UzkgeError::SetupError)?;
            Ok(cm)
        }
    };

    // Step 1: compute permutation polynomials and commit them.
    let raw_perm = if let Some(perm) = permutation {
        perm
    } else {
        cs.compute_permutation()
    };
    let mut encoded_perm = Vec::with_capacity(n_wires_per_gate * n);
    for i in 0..n_wires_per_gate {
        encoded_perm.extend(encode_perm_to_group(
            &group,
            &raw_perm[i * n..(i + 1) * n],
            &k,
        ));
    }
    let mut s_coset_evals = vec![vec![]; n_wires_per_gate];
    let mut s_polys = vec![];
    let mut cm_s_vec = vec![];
    for i in 0..n_wires_per_gate {
        let s_coefs = FpPolynomial::ifft_with_domain(&domain, &encoded_perm[i * n..(i + 1) * n]);

        s_coset_evals[i].extend(s_coefs.coset_fft_with_domain(&domain_m, &k[1]));

        if no_verifier {
            let cm_s = commit(encoded_perm[i * n..(i + 1) * n].to_vec(), &s_coefs)?;
            cm_s_vec.push(cm_s);
        }

        s_polys.push(s_coefs);
    }

    // Step 2: compute selector polynomials and commit them.
    let mut q_coset_evals = vec![vec![]; CS::num_selectors()];
    let mut q_polys = vec![];
    let mut cm_q_vec = vec![];
    for (i, q_coset_eval) in q_coset_evals.iter_mut().enumerate() {
        let q_coefs = FpPolynomial::ifft_with_domain(&domain, cs.selector(i)?);
        q_coset_eval.extend(q_coefs.coset_fft_with_domain(&domain_m, &k[1]));

        if no_verifier {
            let cm_q = commit(cs.selector(i)?.to_vec(), &q_coefs)?;
            cm_q_vec.push(cm_q);
        }
        q_polys.push(q_coefs);
    }

    // Step 3: precompute two helper functions, L1 and Z_H.
    let mut l1_evals = FpPolynomial::from_coefs(vec![PCS::Field::zero(); group.len()]);
    l1_evals.coefs[0] = PCS::Field::from(n as u32); // X^n - 1 = (X - 1) (X^{n-1} + X^{n-2} + ... + 1)
    let l1_coefs = FpPolynomial::ifft_with_domain(&domain, &l1_evals.coefs);
    let l1_coset_evals = l1_coefs.coset_fft_with_domain(&domain_m, &k[1]);

    let z_h_coefs = {
        let mut v = vec![PCS::Field::zero(); n + 1];
        v[0] = PCS::Field::one().neg();
        v[n] = PCS::Field::one();
        FpPolynomial::from_coefs(v)
    };
    let z_h_inv_coset_evals = z_h_coefs
        .coset_fft_with_domain(&domain_m, &k[1])
        .into_iter()
        .map(|x| x.inverse().unwrap())
        .collect();

    // Step 4: compute the Lagrange interpolation constants.
    let mut lagrange_constants = vec![];
    if no_verifier {
        for constraint_index in cs.public_vars_constraint_indices().iter() {
            lagrange_constants.push(compute_lagrange_constant(&group, *constraint_index));
        }
    }

    // Step 5: commit `boolean_constraint_indices`.
    let (qb_coset_eval, qb_poly, cm_qb) = {
        let mut qb = vec![PCS::Field::zero(); n];
        for i in cs.boolean_constraint_indices().iter() {
            qb[*i] = PCS::Field::one();
        }
        let qb_coef = FpPolynomial::ifft_with_domain(&domain, &qb);
        let qb_coset_eval = qb_coef.coset_fft_with_domain(&domain_m, &k[1]);

        let cm_qb = if no_verifier {
            commit(qb, &qb_coef)?
        } else {
            Default::default()
        };

        (qb_coset_eval, qb_coef, cm_qb)
    };

    // Step 6: commit `anemoi_constraints_indices`
    let (q_prk_coset_evals, q_prk_polys, cm_prk_vec) = {
        let q_prk_evals = cs.compute_anemoi_jive_selectors().to_vec();

        let q_prk_polys: Vec<FpPolynomial<PCS::Field>> = q_prk_evals
            .iter()
            .map(|p| FpPolynomial::ifft_with_domain(&domain, &p))
            .collect::<Vec<FpPolynomial<PCS::Field>>>();

        let q_prk_coset_evals = q_prk_polys
            .iter()
            .map(|p| p.coset_fft_with_domain(&domain_m, &k[1]))
            .collect::<Vec<Vec<PCS::Field>>>();

        let cm_prk_vec: Vec<PCS::Commitment> = if no_verifier {
            q_prk_evals
                .into_iter()
                .zip(q_prk_polys.iter())
                .map(|(q_prk_eval, q_prk_poly)| commit(q_prk_eval, q_prk_poly))
                .collect::<Result<_, UzkgeError>>()?
        } else {
            vec![]
        };

        (q_prk_coset_evals, q_prk_polys, cm_prk_vec)
    };

    // Step 7: commit `shuffle_remark_constraint_indices`
    #[cfg(feature = "shuffle")]
    let (q_ecc_coset_eval, q_ecc_poly, cm_q_ecc) = {
        let mut q_ecc = vec![PCS::Field::zero(); n];
        for i in cs.shuffle_remark_constraint_indices().iter() {
            for j in 0..cs.n_iteration_shuffle_scalar_mul() {
                q_ecc[*i + j] = PCS::Field::one();
            }
        }
        let q_ecc_coef = FpPolynomial::ifft_with_domain(&domain, &q_ecc);
        let q_ecc_coset_eval = q_ecc_coef.coset_fft_with_domain(&domain_m, &k[1]);

        let cm_q_ecc = if no_verifier {
            commit(q_ecc, &q_ecc_coef)?
        } else {
            Default::default()
        };

        (q_ecc_coset_eval, q_ecc_coef, cm_q_ecc)
    };

    // Step 8: compute polynomials related to shuffle and commit them.
    #[cfg(feature = "shuffle")]
    let (q_shuffle_generator_coset_evals, q_shuffle_generator_polys, cm_shuffle_generator_vec) = {
        let q_shuffle_generator_evals = cs.compute_shuffle_generator_selectors();

        let q_shuffle_generator_polys: Vec<FpPolynomial<PCS::Field>> = q_shuffle_generator_evals
            .iter()
            .map(|p| FpPolynomial::ifft_with_domain(&domain, &p))
            .collect::<Vec<FpPolynomial<PCS::Field>>>();

        let q_shuffle_generator_coset_evals = q_shuffle_generator_polys
            .iter()
            .map(|p| p.coset_fft_with_domain(&domain_m, &k[1]))
            .collect::<Vec<Vec<PCS::Field>>>();

        let cm_shuffle_generator_vec: Vec<PCS::Commitment> = if no_verifier {
            q_shuffle_generator_evals
                .into_iter()
                .zip(q_shuffle_generator_polys.iter())
                .map(|(q_shuffle_generator_eval, q_shuffle_generator_poly)| {
                    commit(q_shuffle_generator_eval, q_shuffle_generator_poly)
                })
                .collect::<Result<_, UzkgeError>>()?
        } else {
            vec![]
        };

        (
            q_shuffle_generator_coset_evals,
            q_shuffle_generator_polys,
            cm_shuffle_generator_vec,
        )
    };

    //  Step 9: fake public key paramaters with generator paramaters.
    #[cfg(feature = "shuffle")]
    let q_shuffle_public_key_polys = q_shuffle_generator_polys.clone();
    #[cfg(feature = "shuffle")]
    let q_shuffle_public_key_coset_evals = q_shuffle_generator_coset_evals.clone();
    #[cfg(feature = "shuffle")]
    let cm_shuffle_public_key_vec = cm_shuffle_generator_vec.clone();

    let verifier_params = if let Some(verifier) = verifier_params {
        verifier
    } else {
        let (anemoi_generator, anemoi_generator_inv) = cs.get_anemoi_parameters();
        PlonkVerifierParams {
            cm_q_vec,
            cm_s_vec,
            cm_qb,
            cm_prk_vec,
            #[cfg(feature = "shuffle")]
            cm_q_ecc,
            #[cfg(feature = "shuffle")]
            cm_shuffle_generator_vec,
            #[cfg(feature = "shuffle")]
            cm_shuffle_public_key_vec,
            anemoi_generator,
            anemoi_generator_inv,
            k,
            #[cfg(feature = "shuffle")]
            edwards_a: cs.get_edwards_a(),
            cs_size: n,
            public_vars_constraint_indices: cs.public_vars_constraint_indices().to_vec(),
            lagrange_constants,
        }
    };

    Ok(PlonkProverParams {
        q_polys,
        s_polys,
        qb_poly,
        q_prk_polys,
        #[cfg(feature = "shuffle")]
        q_ecc_poly,
        #[cfg(feature = "shuffle")]
        q_shuffle_generator_polys,
        #[cfg(feature = "shuffle")]
        q_shuffle_public_key_polys,
        permutation: raw_perm,
        verifier_params,
        group,
        coset_quotient,
        l1_coefs,
        l1_coset_evals,
        z_h_coefs,
        z_h_inv_coset_evals,
        q_coset_evals,
        s_coset_evals,
        qb_coset_eval,
        q_prk_coset_evals,
        #[cfg(feature = "shuffle")]
        q_ecc_coset_eval,
        #[cfg(feature = "shuffle")]
        q_shuffle_generator_coset_evals,
        #[cfg(feature = "shuffle")]
        q_shuffle_public_key_coset_evals,
    })
}

impl PlonkProof<KZGCommitmentSchemeBN254> {
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut bytes = vec![];

        for p in &self.cm_w_vec {
            bytes.append(&mut point_to_uncompress_be(&p.0));
        }

        #[cfg(feature = "shuffle")]
        for p in &self.cm_w_sel_vec {
            bytes.append(&mut point_to_uncompress_be(&p.0));
        }

        for p in &self.cm_t_vec {
            bytes.append(&mut point_to_uncompress_be(&p.0));
        }

        bytes.append(&mut point_to_uncompress_be(&self.cm_z.0));

        bytes.append(&mut scalar_to_bytes_be(&self.prk_3_poly_eval_zeta));

        bytes.append(&mut scalar_to_bytes_be(&self.prk_4_poly_eval_zeta));

        for s in &self.w_polys_eval_zeta {
            bytes.append(&mut scalar_to_bytes_be(s));
        }

        for s in &self.w_polys_eval_zeta_omega {
            bytes.append(&mut scalar_to_bytes_be(s));
        }

        bytes.append(&mut scalar_to_bytes_be(&self.z_eval_zeta_omega));

        for s in &self.s_polys_eval_zeta {
            bytes.append(&mut scalar_to_bytes_be(s));
        }

        #[cfg(feature = "shuffle")]
        bytes.append(&mut scalar_to_bytes_be(&self.q_ecc_poly_eval_zeta));

        #[cfg(feature = "shuffle")]
        for s in &self.w_sel_polys_eval_zeta {
            bytes.append(&mut scalar_to_bytes_be(s));
        }

        bytes.append(&mut point_to_uncompress_be(&self.opening_witness_zeta.0));

        bytes.append(&mut point_to_uncompress_be(
            &self.opening_witness_zeta_omega.0,
        ));

        bytes
    }

    pub fn from_bytes_be<CS: ConstraintSystem<Fr>>(bytes: &[u8]) -> Result<Self, UzkgeError> {
        let n = G1Projective::generator().uncompressed_size();
        let m = Fr::one().uncompressed_size();
        let n_wire = CS::n_wires_per_gate();

        #[cfg(feature = "shuffle")]
        let n_selector = CS::num_wire_selectors();

        let mut bytes_len = 0;

        bytes_len += n * n_wire; // cm_w_vec,
        #[cfg(feature = "shuffle")]
        {
            bytes_len += n * n_selector; // cm_w_sel_vec,
        }
        bytes_len += n * n_wire; // cm_t_vec,
        bytes_len += n; // cm_z,
        bytes_len += m; // prk_3_poly_eval_zeta,
        bytes_len += m; // prk_4_poly_eval_zeta,
        bytes_len += m * n_wire; // w_polys_eval_zeta,
        bytes_len += m * 3; // w_polys_eval_zeta_omega,
        bytes_len += m; // z_eval_zeta_omega,
        bytes_len += m * (n_wire - 1); // s_polys_eval_zeta,
        #[cfg(feature = "shuffle")]
        {
            bytes_len += m; // q_ecc_poly_eval_zeta,
        }
        #[cfg(feature = "shuffle")]
        {
            bytes_len += m * n_selector; // w_sel_polys_eval_zeta,
        }
        bytes_len += n; // opening_witness_zeta,
        bytes_len += n; // opening_witness_zeta_omega,

        if bytes.len() < bytes_len {
            return Err(UzkgeError::DeserializationError);
        }

        let mut p = 0;

        let mut cm_w_vec = vec![];
        for _ in 0..n_wire {
            cm_w_vec.push(KZGCommitment(point_from_uncompress_be(
                &bytes[p..p + n],
                false,
            )?));
            p += n;
        }

        #[cfg(feature = "shuffle")]
        let mut cm_w_sel_vec = vec![];
        #[cfg(feature = "shuffle")]
        for _ in 0..n_selector {
            cm_w_sel_vec.push(KZGCommitment(point_from_uncompress_be(
                &bytes[p..p + n],
                false,
            )?));
            p += n;
        }

        let mut cm_t_vec = vec![];
        for _ in 0..n_wire {
            cm_t_vec.push(KZGCommitment(point_from_uncompress_be(
                &bytes[p..p + n],
                false,
            )?));
            p += n;
        }

        let cm_z = KZGCommitment(point_from_uncompress_be(&bytes[p..p + n], false)?);
        p += n;

        let prk_3_poly_eval_zeta = scalar_from_bytes_be(&bytes[p..p + m], false)?;
        p += m;

        let prk_4_poly_eval_zeta = scalar_from_bytes_be(&bytes[p..p + m], false)?;
        p += m;

        let mut w_polys_eval_zeta = vec![];
        for _ in 0..n_wire {
            w_polys_eval_zeta.push(scalar_from_bytes_be(&bytes[p..p + m], false)?);
            p += m;
        }

        let mut w_polys_eval_zeta_omega = vec![];
        for _ in 0..3 {
            w_polys_eval_zeta_omega.push(scalar_from_bytes_be(&bytes[p..p + m], false)?);
            p += m;
        }

        let z_eval_zeta_omega = scalar_from_bytes_be(&bytes[p..p + m], false)?;
        p += m;

        let mut s_polys_eval_zeta = vec![];
        for _ in 0..n_wire - 1 {
            s_polys_eval_zeta.push(scalar_from_bytes_be(&bytes[p..p + m], false)?);
            p += m;
        }

        #[cfg(feature = "shuffle")]
        let q_ecc_poly_eval_zeta = scalar_from_bytes_be(&bytes[p..p + m], false)?;
        #[cfg(feature = "shuffle")]
        {
            p += m;
        }

        #[cfg(feature = "shuffle")]
        let mut w_sel_polys_eval_zeta = vec![];
        #[cfg(feature = "shuffle")]
        for _ in 0..n_selector {
            w_sel_polys_eval_zeta.push(scalar_from_bytes_be(&bytes[p..p + m], false)?);
            p += m;
        }

        let opening_witness_zeta =
            KZGCommitment(point_from_uncompress_be(&bytes[p..p + n], false)?);
        p += n;

        let opening_witness_zeta_omega =
            KZGCommitment(point_from_uncompress_be(&bytes[p..p + n], false)?);

        Ok(PlonkProof {
            cm_w_vec,
            #[cfg(feature = "shuffle")]
            cm_w_sel_vec,
            cm_t_vec,
            cm_z,
            prk_3_poly_eval_zeta,
            prk_4_poly_eval_zeta,
            w_polys_eval_zeta,
            w_polys_eval_zeta_omega,
            z_eval_zeta_omega,
            s_polys_eval_zeta,
            #[cfg(feature = "shuffle")]
            q_ecc_poly_eval_zeta,
            #[cfg(feature = "shuffle")]
            w_sel_polys_eval_zeta,
            opening_witness_zeta,
            opening_witness_zeta_omega,
        })
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::Fr;
    use rand_chacha::ChaChaRng;

    use super::*;

    type F = Fr;

    #[test]
    fn test_choose_ks() {
        let mut prng = ChaChaRng::from_entropy();
        let m = 8;
        let k = choose_ks::<_, F>(&mut prng, m);
        let mut q_minus_1_half_le = F::MODULUS.to_bytes_le();
        shift_u8_vec(&mut q_minus_1_half_le);
        let exp = u64_limbs_from_bytes(&q_minus_1_half_le);
        assert_eq!(k[0], F::one());
        assert!(k.iter().skip(1).all(|x| *x != F::zero()));
        assert!(k.iter().skip(1).all(|x| x.pow(&exp) != F::one()));
        for i in 1..m {
            for j in 0..i {
                assert_ne!(k[i], k[j]);
            }
        }
    }
}
