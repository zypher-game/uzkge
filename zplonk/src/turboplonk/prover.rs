use ark_poly::Radix2EvaluationDomain;
use ark_std::{
    ops::*,
    rand::{CryptoRng, RngCore},
};

use crate::{
    errors::ZplonkError,
    poly_commit::{field_polynomial::FpPolynomial, pcs::PolyComScheme},
    turboplonk::helpers::{
        first_lagrange_poly, hide_polynomial, pi_poly, r_poly, split_t_and_commit, t_poly, z_poly,
        PlonkChallenges,
    },
    utils::transcript::Transcript,
};

use super::{
    constraint_system::ConstraintSystem,
    indexer::{PlonkProof, PlonkProverParams},
    transcript::transcript_init_plonk,
};

/// PLONK Prover: it produces a proof that `witness` satisfies the constraint system `cs`,
/// Proof verifier must use a transcript with same state as prover and match the public parameters,
/// It returns [PlonkError] if an error occurs in computing proof commitments, meaning parameters of the polynomial
/// commitment scheme `pcs` do not match the constraint system parameters.
/// # Example
/// ```
/// use zplonk::turboplonk::{
///     constraint_system::TurboCS,
///     verifier::verifier,
///     prover::prover,
///     indexer::indexer
/// };
/// use zplonk::poly_commit::kzg_poly_commitment::KZGCommitmentScheme;
/// use zplonk::utils::transcript::Transcript;
/// use rand_chacha::ChaChaRng;
/// use ark_bn254::Fr;
/// use ark_std::{One, rand::SeedableRng, ops::*};
///
/// let mut prng = ChaChaRng::from_seed([0u8; 32]);
/// let pcs = KZGCommitmentScheme::new(20, &mut prng);
/// let mut cs = TurboCS::new();
///
/// // circuit (x_0 + x_1);
/// let one = Fr::one();
/// let two = one.add(&one);
/// let three = two.add(&one);
/// let var_one = cs.new_variable(one);
/// let var_two = cs.new_variable(two);
/// let var_three = cs.new_variable(three);
/// cs.insert_add_gate(var_one, var_two, var_three);
/// cs.pad();
///
/// let witness = cs.get_and_clear_witness();
/// let prover_params = indexer(&cs, &pcs).unwrap();
///
/// let proof = {
///     let mut transcript = Transcript::new(b"Test");
///     prover(
///         &mut prng,
///         &mut transcript,
///         &pcs,
///         &cs,
///         &prover_params,
///         &witness,
///     )
///         .unwrap()
/// };
///
/// let mut transcript = Transcript::new(b"Test");
/// assert!(
///     verifier(&mut transcript, &pcs, &cs, &prover_params.get_verifier_params(), &[], &proof).is_ok()
/// )
/// ```
pub fn prover<R: CryptoRng + RngCore, PCS: PolyComScheme, CS: ConstraintSystem<PCS::Field>>(
    prng: &mut R,
    transcript: &mut Transcript,
    pcs: &PCS,
    cs: &CS,
    params: &PlonkProverParams<PCS>,
    witness: &[PCS::Field],
) -> Result<PlonkProof<PCS>, ZplonkError> {
    prover_with_lagrange(prng, transcript, pcs, None, cs, params, witness)
}

/// Prover that uses Lagrange bases
pub fn prover_with_lagrange<
    R: CryptoRng + RngCore,
    PCS: PolyComScheme,
    CS: ConstraintSystem<PCS::Field>,
>(
    prng: &mut R,
    transcript: &mut Transcript,
    pcs: &PCS,
    lagrange_pcs: Option<&PCS>,
    cs: &CS,
    prover_params: &PlonkProverParams<PCS>,
    w: &[PCS::Field],
) -> Result<PlonkProof<PCS>, ZplonkError> {
    if cs.is_verifier_only() {
        return Err(ZplonkError::FuncParamsError);
    }

    let domain = FpPolynomial::<PCS::Field>::evaluation_domain(cs.size())
        .ok_or(ZplonkError::GroupNotFound(cs.size()))?;
    let root = domain.group_gen;

    let online_values: Vec<PCS::Field> = cs
        .public_vars_witness_indices()
        .iter()
        .map(|index| w[*index])
        .collect();

    // Init transcript
    transcript_init_plonk(
        transcript,
        &prover_params.verifier_params,
        &online_values,
        &root,
    );
    let mut challenges = PlonkChallenges::new();
    let n_constraints = cs.size();

    let lagrange_pcs =
        if lagrange_pcs.is_some() && lagrange_pcs.unwrap().max_degree() + 1 == n_constraints {
            lagrange_pcs
        } else {
            None
        };

    let commit = |evals: Vec<PCS::Field>,
                  coef_polynomial: &FpPolynomial<PCS::Field>,
                  blinds: &[PCS::Field]|
     -> Result<PCS::Commitment, ZplonkError> {
        if let Some(lagrange_pcs) = lagrange_pcs {
            let eval_poly = FpPolynomial::from_coefs(evals);
            let cm = lagrange_pcs
                .commit(&eval_poly)
                .map_err(|_| ZplonkError::SetupError)?;
            let cm = pcs.apply_blind_factors(&cm, &blinds, n_constraints);
            Ok(cm)
        } else {
            let cm = pcs
                .commit(&coef_polynomial)
                .map_err(|_| ZplonkError::SetupError)?;
            Ok(cm)
        }
    };

    // 1. Build the PI polynomial
    let pi = pi_poly::<PCS, Radix2EvaluationDomain<_>>(&prover_params, &online_values, &domain);

    // 2. build witness polynomials, hide them and commit
    let extended_witness = cs.extend_witness(w); /* Prepare extended witness */
    let n_wires_per_gate = CS::n_wires_per_gate();
    let mut w_polys = vec![];
    let mut cm_w_vec = vec![];

    for i in 0..n_wires_per_gate {
        let mut f_coefs = FpPolynomial::ifft_with_domain(
            &domain,
            &extended_witness[i * n_constraints..(i + 1) * n_constraints],
        );
        let blinds = hide_polynomial(prng, &mut f_coefs, cs.get_hiding_degree(i), n_constraints);
        let cm_w = commit(
            extended_witness[i * n_constraints..(i + 1) * n_constraints].to_vec(),
            &f_coefs,
            &blinds,
        )?;
        transcript.append_commitment::<PCS::Commitment>(&cm_w);

        w_polys.push(f_coefs);
        cm_w_vec.push(cm_w);
    }

    // 3. build witness selector polynomials, hide them and commit
    #[cfg(feature = "shuffle")]
    let mut w_sel_polys = vec![];
    #[cfg(feature = "shuffle")]
    let mut cm_w_sel_vec = vec![];

    #[cfg(feature = "shuffle")]
    for witness_selector in cs.compute_witness_selectors().iter() {
        let mut f_coefs = FpPolynomial::ifft_with_domain(&domain, witness_selector);
        let blinds = hide_polynomial(prng, &mut f_coefs, 2, n_constraints);
        let cm_w_sel = commit(witness_selector.to_vec(), &f_coefs, &blinds)?;
        transcript.append_commitment::<PCS::Commitment>(&cm_w_sel);

        w_sel_polys.push(f_coefs);
        cm_w_sel_vec.push(cm_w_sel);
    }

    // 4. get challenges beta and gamma
    let beta = transcript.get_challenge_field_elem(b"beta");
    transcript.append_single_byte(b"gamma", 0x01);
    let gamma = transcript.get_challenge_field_elem(b"gamma");
    challenges.insert_beta_gamma(beta, gamma).unwrap(); // safe unwrap

    // 5. build the z polynomial, hide it and commit
    let (cm_z, z_poly) = {
        let z_evals = z_poly::<PCS, CS>(prover_params, &extended_witness, &challenges);
        let mut z_coefs = FpPolynomial::ifft_with_domain(&domain, &z_evals.coefs);
        let blinds = hide_polynomial(prng, &mut z_coefs, 3, n_constraints);
        let cm_z = commit(z_evals.coefs, &z_coefs, &blinds)?;
        transcript.append_commitment::<PCS::Commitment>(&cm_z);

        (cm_z, z_coefs)
    };

    // 6. get challenge alpha
    let alpha = transcript.get_challenge_field_elem(b"alpha");
    challenges.insert_alpha(alpha).unwrap();

    // 7. build t, split into `n_wires_per_gate` degree-(N+2) polynomials and commit
    let t_poly = t_poly::<PCS, CS>(
        cs,
        prover_params,
        &w_polys,
        #[cfg(feature = "shuffle")]
        &w_sel_polys,
        &z_poly,
        &challenges,
        &pi,
    )?;

    let (cm_t_vec, t_polys) = split_t_and_commit(
        prng,
        pcs,
        lagrange_pcs,
        &t_poly,
        n_wires_per_gate,
        n_constraints + 2,
    )?;

    for cm_t in cm_t_vec.iter() {
        transcript.append_commitment::<PCS::Commitment>(cm_t);
    }

    // 8. get challenge zeta
    let zeta = transcript.get_challenge_field_elem(b"zeta");
    challenges.insert_zeta(zeta).unwrap();

    // 9. a) Evaluate the openings of witness/permutation polynomials at \zeta, and
    // evaluate the opening of z(X) at point \omega * \zeta.
    let w_polys_eval_zeta: Vec<PCS::Field> =
        w_polys.iter().map(|poly| pcs.eval(poly, &zeta)).collect();
    let s_polys_eval_zeta: Vec<PCS::Field> = prover_params
        .s_polys
        .iter()
        .take(n_wires_per_gate - 1)
        .map(|poly| pcs.eval(poly, &zeta))
        .collect();

    let prk_3_poly_eval_zeta = pcs.eval(&prover_params.q_prk_polys[2], &zeta);
    let prk_4_poly_eval_zeta = pcs.eval(&prover_params.q_prk_polys[3], &zeta);

    let zeta_omega = root.mul(&zeta);
    let z_eval_zeta_omega = pcs.eval(&z_poly, &zeta_omega);

    let w_polys_eval_zeta_omega: Vec<PCS::Field> = w_polys
        .iter()
        .take(3)
        .map(|poly| pcs.eval(poly, &zeta_omega))
        .collect();

    #[cfg(feature = "shuffle")]
    let q_ecc_poly_eval_zeta = pcs.eval(&prover_params.q_ecc_poly, &zeta);
    #[cfg(feature = "shuffle")]
    let w_sel_polys_eval_zeta: Vec<PCS::Field> = w_sel_polys
        .iter()
        .map(|poly| pcs.eval(poly, &zeta))
        .collect();

    //  b). build the r polynomial, and eval at zeta
    for eval_zeta in w_polys_eval_zeta.iter().chain(s_polys_eval_zeta.iter()) {
        transcript.append_challenge(eval_zeta);
    }

    #[cfg(feature = "shuffle")]
    for eval_zeta in w_sel_polys_eval_zeta.iter() {
        transcript.append_challenge(eval_zeta);
    }

    transcript.append_challenge(&prk_3_poly_eval_zeta);
    transcript.append_challenge(&prk_4_poly_eval_zeta);
    transcript.append_challenge(&z_eval_zeta_omega);
    #[cfg(feature = "shuffle")]
    transcript.append_challenge(&q_ecc_poly_eval_zeta);
    for eval_zeta_omega in w_polys_eval_zeta_omega.iter() {
        transcript.append_challenge(eval_zeta_omega);
    }

    // 10. get challenge u
    let u = transcript.get_challenge_field_elem(b"u");
    challenges.insert_u(u).unwrap();

    let w_polys_eval_zeta_as_ref: Vec<&PCS::Field> = w_polys_eval_zeta.iter().collect();
    #[cfg(feature = "shuffle")]
    let w_polys_eval_zeta_omega_as_ref: Vec<&PCS::Field> = w_polys_eval_zeta_omega.iter().collect();
    let s_poly_eval_zeta_as_ref: Vec<&PCS::Field> = s_polys_eval_zeta.iter().collect();
    #[cfg(feature = "shuffle")]
    let w_sel_polys_eval_zeta_as_ref: Vec<&PCS::Field> = w_sel_polys_eval_zeta.iter().collect();

    let (z_h_eval_zeta, first_lagrange_eval_zeta) =
        first_lagrange_poly::<PCS>(&challenges, cs.size() as u64);
    let r_poly = r_poly::<PCS, CS>(
        prover_params,
        &z_poly,
        &w_polys_eval_zeta_as_ref,
        #[cfg(feature = "shuffle")]
        &w_polys_eval_zeta_omega_as_ref,
        &s_poly_eval_zeta_as_ref,
        &prk_3_poly_eval_zeta,
        &z_eval_zeta_omega,
        #[cfg(feature = "shuffle")]
        &q_ecc_poly_eval_zeta,
        #[cfg(feature = "shuffle")]
        &w_sel_polys_eval_zeta_as_ref,
        &challenges,
        &t_polys,
        &first_lagrange_eval_zeta,
        &z_h_eval_zeta,
        #[cfg(feature = "shuffle")]
        &cs.get_edwards_a(),
        n_constraints + 2,
    );

    let mut polys_to_open: Vec<&FpPolynomial<PCS::Field>> = w_polys
        .iter()
        .chain(
            prover_params
                .s_polys
                .iter()
                .take(CS::n_wires_per_gate() - 1),
        )
        .collect();
    polys_to_open.push(&prover_params.q_prk_polys[2]);
    polys_to_open.push(&prover_params.q_prk_polys[3]);
    #[cfg(feature = "shuffle")]
    {
        polys_to_open.push(&prover_params.q_ecc_poly);
        for w_sel_poly in w_sel_polys.iter() {
            polys_to_open.push(w_sel_poly);
        }
    }
    polys_to_open.push(&r_poly);

    let zeta = challenges.get_zeta().unwrap();

    let opening_witness_zeta = pcs
        .batch_prove(
            transcript,
            lagrange_pcs,
            &polys_to_open[..],
            &zeta,
            n_constraints + 2,
        )
        .map_err(|_| ZplonkError::ProofError)?;

    let polys_to_open: Vec<&FpPolynomial<PCS::Field>> =
        vec![&z_poly, &w_polys[0], &w_polys[1], &w_polys[2]];

    let opening_witness_zeta_omega = pcs
        .batch_prove(
            transcript,
            lagrange_pcs,
            &polys_to_open[..],
            &zeta_omega,
            n_constraints + 2,
        )
        .map_err(|_| ZplonkError::ProofError)?;

    // return proof
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
