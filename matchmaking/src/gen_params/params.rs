use ark_bn254::Fr;
use ark_ff::Zero;
use uzkge::{
    errors::UzkgeError,
    gen_params::{
        load_lagrange_params, load_srs_params, VerifierParamsSplitCommon,
        VerifierParamsSplitSpecific, VERIFIER_COMMON_PARAMS,
    },
    plonk::{constraint_system::ConstraintSystem, indexer::indexer_with_lagrange},
};

use crate::{
    build_cs::{build_cs, N},
    gen_params::VERIFIER_SPECIFIC_PARAMS,
};

// re-export
pub use uzkge::gen_params::{ProverParams, VerifierParams};

/// Obtain the parameters for prover.
pub fn gen_prover_params() -> Result<ProverParams, UzkgeError> {
    let (cs, _) = build_cs(&[Fr::zero(); N], &Fr::zero(), &Fr::zero());
    let pcs = load_srs_params(cs.size())?;
    let lagrange_pcs = load_lagrange_params(cs.size());

    let verifier_params = if let Ok(v) = load_verifier_params() {
        Some(v.verifier_params)
    } else {
        None
    };

    let prover_params =
        indexer_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), None, verifier_params).unwrap();

    Ok(ProverParams {
        pcs,
        lagrange_pcs,
        cs,
        prover_params,
    })
}

/// Get the verifier parameters.
pub fn get_verifier_params() -> Result<VerifierParams, UzkgeError> {
    match load_verifier_params() {
        Ok(vk) => Ok(vk),
        Err(_e) => Ok(VerifierParams::from(gen_prover_params()?)),
    }
}

/// Load the verifier parameters from prepare.
pub fn load_verifier_params() -> Result<VerifierParams, UzkgeError> {
    match (VERIFIER_COMMON_PARAMS, VERIFIER_SPECIFIC_PARAMS) {
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
