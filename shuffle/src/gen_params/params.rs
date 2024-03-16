use ark_bn254::G1Projective;
use ark_ed_on_bn254::EdwardsProjective;
use ark_std::{rand::SeedableRng, UniformRand};
use rand_chacha::ChaChaRng;
use uzkge::{
    errors::UzkgeError,
    gen_params::{
        load_lagrange_params, load_srs_params, VerifierParamsSplitCommon,
        VerifierParamsSplitSpecific, VERIFIER_COMMON_PARAMS,
    },
    plonk::{constraint_system::ConstraintSystem, indexer::indexer_with_lagrange},
};

use crate::{
    build_cs::build_cs,
    gen_params::{VERIFIER_SPECIFIC_PARAMS_52, VERIFIER_SPECIFIC_PARAMS_54},
    MaskedCard,
};

// re-export
pub use uzkge::gen_params::{ProverParams, VerifierParams};

/// Obtain the parameters for shuffle.
pub fn gen_shuffle_prover_params(n: usize) -> Result<ProverParams, UzkgeError> {
    let mut rng = ChaChaRng::from_seed([0u8; 32]);
    let apk = EdwardsProjective::rand(&mut rng);
    let cards = vec![MaskedCard::rand(&mut rng); n];
    let (cs, _) = build_cs(&mut rng, &apk, &cards);

    let cs_size = cs.size();
    let pcs = load_srs_params(cs_size)?;
    let lagrange_pcs = load_lagrange_params(cs_size);

    let verifier_params = if let Ok(v) = load_shuffle_verifier_params(n) {
        Some(v.verifier_params)
    } else {
        None
    };

    let prover_params =
        indexer_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), verifier_params).unwrap();

    Ok(ProverParams {
        pcs,
        lagrange_pcs,
        cs,
        prover_params,
    })
}

/// Refresh the public key for shuffle.
pub fn refresh_prover_params_public_key(
    params: &mut ProverParams,
    shuffle_pk: &EdwardsProjective,
) -> Result<Vec<G1Projective>, UzkgeError> {
    use ark_bn254::Fr;
    use uzkge::{
        poly_commit::{field_polynomial::FpPolynomial, pcs::PolyComScheme},
        shuffle::BabyJubjubShuffle,
    };

    params
        .cs
        .load_shuffle_remark_parameters::<_, BabyJubjubShuffle>(shuffle_pk);

    let n = params.cs.size();
    let m = params.cs.quot_eval_dom_size();
    if m % n != 0 {
        return Err(UzkgeError::ParameterError);
    }

    let pcs = load_srs_params(n)?;
    let lagrange_pcs = load_lagrange_params(n);
    let lagrange_pcs = lagrange_pcs.as_ref();
    let lagrange_pcs = if lagrange_pcs.is_some() && lagrange_pcs.unwrap().max_degree() + 1 == n {
        lagrange_pcs
    } else {
        None
    };

    let domain = FpPolynomial::evaluation_domain(n).ok_or(UzkgeError::ParameterError)?;
    let domain_m =
        FpPolynomial::quotient_evaluation_domain(m).ok_or(UzkgeError::ParameterError)?;

    let q_shuffle_public_key_evals = params.cs.compute_shuffle_public_key_selectors();

    let q_shuffle_public_key_polys: Vec<FpPolynomial<Fr>> = q_shuffle_public_key_evals
        .iter()
        .map(|p| FpPolynomial::ifft_with_domain(&domain, &p))
        .collect::<Vec<FpPolynomial<Fr>>>();

    let q_shuffle_public_key_coset_evals = q_shuffle_public_key_polys
        .iter()
        .map(|p| p.coset_fft_with_domain(&domain_m, &params.prover_params.verifier_params.k[1]))
        .collect::<Vec<Vec<Fr>>>();

    let mut cm_shuffle_public_key_vec = vec![];
    for (q_shuffle_public_key_eval, q_shuffle_public_key_poly) in q_shuffle_public_key_evals
        .into_iter()
        .zip(q_shuffle_public_key_polys.iter())
    {
        if let Some(lagrange_pcs) = lagrange_pcs {
            let eval_poly = FpPolynomial::from_coefs(q_shuffle_public_key_eval);
            let cm = lagrange_pcs
                .commit(&eval_poly)
                .map_err(|_| UzkgeError::ParameterError)?;
            cm_shuffle_public_key_vec.push(cm)
        } else {
            let cm = pcs
                .commit(&q_shuffle_public_key_poly)
                .map_err(|_| UzkgeError::ParameterError)?;
            cm_shuffle_public_key_vec.push(cm)
        }
    }
    let res: Vec<_> = cm_shuffle_public_key_vec.iter().map(|c| c.0).collect();

    params.prover_params.q_shuffle_public_key_polys = q_shuffle_public_key_polys;
    params.prover_params.q_shuffle_public_key_coset_evals = q_shuffle_public_key_coset_evals;
    params
        .prover_params
        .verifier_params
        .cm_shuffle_public_key_vec = cm_shuffle_public_key_vec;

    Ok(res)
}

/// Parse the verifier parameters from bytes.
pub fn parse_shuffle_verifier_params(vk: &[u8]) -> Result<VerifierParams, UzkgeError> {
    bincode::deserialize(vk).map_err(|_| UzkgeError::DeserializationError)
}

/// Get the verifier parameters.
pub fn get_shuffle_verifier_params(n: usize) -> Result<VerifierParams, UzkgeError> {
    match load_shuffle_verifier_params(n) {
        Ok(vk) => Ok(vk),
        Err(_e) => Ok(VerifierParams::from(gen_shuffle_prover_params(n)?)),
    }
}

/// Load the verifier parameters from prepare.
pub fn load_shuffle_verifier_params(n: usize) -> Result<VerifierParams, UzkgeError> {
    let specific = match n {
        52 => VERIFIER_SPECIFIC_PARAMS_52,
        54 => VERIFIER_SPECIFIC_PARAMS_54,
        _ => return Err(UzkgeError::DeserializationError),
    };

    match (VERIFIER_COMMON_PARAMS, specific) {
        (Some(c_bytes), Some(s_bytes)) => {
            let common: VerifierParamsSplitCommon =
                bincode::deserialize(c_bytes).map_err(|_| UzkgeError::DeserializationError)?;

            let special: VerifierParamsSplitSpecific =
                bincode::deserialize(s_bytes).map_err(|_| UzkgeError::DeserializationError)?;

            Ok(VerifierParams {
                shrunk_vk: common.shrunk_pcs,
                shrunk_cs: special.shrunk_cs,
                verifier_params: special.verifier_params,
            })
        }
        _ => Err(UzkgeError::MissingVerifierParamsError),
    }
}
