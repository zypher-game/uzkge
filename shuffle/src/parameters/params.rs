use ark_bn254::Fr;
use ark_ed_on_bn254::EdwardsProjective;
use ark_std::UniformRand;
use zplonk::{
    errors::ZplonkError,
    params::{
        load_lagrange_params, load_srs_params, VerifierParamsSplitCommon,
        VerifierParamsSplitSpecific,
    },
    poly_commit::field_polynomial::FpPolynomial,
    poly_commit::pcs::PolyComScheme,
    shuffle::BabyJubjubShuffle,
    turboplonk::constraint_system::ConstraintSystem,
    turboplonk::indexer::indexer_with_lagrange,
    utils::prelude::*,
};

use crate::build_cs::build_cs;
use crate::parameters::{VERIFIER_COMMON_PARAMS, VERIFIER_SPECIFIC_PARAMS};
use crate::{MaskedCard, N_CARDS};

// re-export
pub use zplonk::params::{ProverParams, VerifierParams};

/// Obtain the parameters for shuffle.
pub fn gen_shuffle_prover_params() -> Result<ProverParams, ZplonkError> {
    let mut rng = ChaChaRng::from_seed([0u8; 32]);
    let apk = EdwardsProjective::rand(&mut rng);
    let cards = [MaskedCard::rand(&mut rng); N_CARDS];
    let (cs, _) = build_cs(&mut rng, &apk, &cards);

    let cs_size = cs.size();
    let pcs = load_srs_params(cs_size)?;
    let lagrange_pcs = load_lagrange_params(cs_size);

    let verifier_params = if let Ok(v) = load_shuffle_verifier_params() {
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

/// Refresh the public key.
pub fn refresh_prover_params_public_key(
    params: &mut ProverParams,
    public_key: &EdwardsProjective,
) -> Result<(), ZplonkError> {
    params
        .cs
        .load_shuffle_remark_parameters::<_, BabyJubjubShuffle>(public_key);

    let n = params.cs.size();
    let m = params.cs.quot_eval_dom_size();
    if m % n != 0 {
        return Err(ZplonkError::ParameterError);
    }

    let pcs = load_srs_params(n)?;
    let lagrange_pcs = load_lagrange_params(n);
    let lagrange_pcs = lagrange_pcs.as_ref();
    let lagrange_pcs = if lagrange_pcs.is_some() && lagrange_pcs.unwrap().max_degree() + 1 == n {
        lagrange_pcs
    } else {
        None
    };

    let domain = FpPolynomial::evaluation_domain(n).ok_or(ZplonkError::ParameterError)?;
    let domain_m =
        FpPolynomial::quotient_evaluation_domain(m).ok_or(ZplonkError::ParameterError)?;

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
                .map_err(|_| ZplonkError::ParameterError)?;
            cm_shuffle_public_key_vec.push(cm)
        } else {
            let cm = pcs
                .commit(&q_shuffle_public_key_poly)
                .map_err(|_| ZplonkError::ParameterError)?;
            cm_shuffle_public_key_vec.push(cm)
        }
    }

    params.prover_params.q_shuffle_public_key_polys = q_shuffle_public_key_polys;
    params.prover_params.q_shuffle_public_key_coset_evals = q_shuffle_public_key_coset_evals;
    params
        .prover_params
        .verifier_params
        .cm_shuffle_public_key_vec = cm_shuffle_public_key_vec;

    Ok(())
}

/// Load the verifier parameters.
pub fn get_shuffle_verifier_params() -> Result<VerifierParams, ZplonkError> {
    match load_shuffle_verifier_params() {
        Ok(vk) => Ok(vk),
        Err(_e) => Ok(VerifierParams::from(gen_shuffle_prover_params()?)),
    }
}

/// Load the verifier parameters from prepare.
pub fn load_shuffle_verifier_params() -> Result<VerifierParams, ZplonkError> {
    match (VERIFIER_COMMON_PARAMS, VERIFIER_SPECIFIC_PARAMS) {
        (Some(c_bytes), Some(s_bytes)) => {
            let common: VerifierParamsSplitCommon =
                bincode::deserialize(c_bytes).map_err(|_| ZplonkError::DeserializationError)?;

            let special: VerifierParamsSplitSpecific =
                bincode::deserialize(s_bytes).map_err(|_| ZplonkError::DeserializationError)?;

            Ok(VerifierParams {
                shrunk_vk: common.shrunk_pcs,
                shrunk_cs: special.shrunk_cs,
                verifier_params: special.verifier_params,
            })
        }
        _ => Err(ZplonkError::MissingVerifierParamsError),
    }
}
