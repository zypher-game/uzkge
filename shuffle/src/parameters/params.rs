use ark_bn254::{Fr, G1Projective};
use ark_ed_on_bn254::EdwardsProjective;
use ark_std::UniformRand;
use zplonk::{
    poly_commit::field_polynomial::FpPolynomial,
    poly_commit::kzg_poly_commitment::KZGCommitmentSchemeBN254,
    poly_commit::pcs::PolyComScheme,
    shuffle::BabyJubjubShuffle,
    turboplonk::constraint_system::ConstraintSystem,
    turboplonk::constraint_system::TurboCS,
    turboplonk::indexer::{indexer_with_lagrange, PlonkProverParams, PlonkVerifierParams},
    utils::prelude::*,
};

use crate::build_cs::build_cs;
use crate::parameters::{SRS, VERIFIER_COMMON_PARAMS, VERIFIER_SPECIFIC_PARAMS};
use crate::{MaskedCard, N_CARDS};

use super::errors::SetUpError;
use super::LAGRANGE_BASES;

#[derive(Serialize, Deserialize)]
/// The verifier parameters.
pub struct VerifierParams {
    /// The shrunk version of the polynomial commitment scheme.
    pub shrunk_vk: KZGCommitmentSchemeBN254,
    /// The shrunk version of the constraint system.
    pub shrunk_cs: TurboCS<Fr>,
    /// The TurboPlonk verifying key.
    pub verifier_params: PlonkVerifierParams<KZGCommitmentSchemeBN254>,
}

#[derive(Serialize, Deserialize)]
/// The common part of the verifier parameters.
pub struct VerifierParamsSplitCommon {
    /// The shrunk version of the polynomial commitment scheme.
    pub shrunk_pcs: KZGCommitmentSchemeBN254,
}

#[derive(Serialize, Deserialize)]
/// The specific part of the verifier parameters.
pub struct VerifierParamsSplitSpecific {
    /// The shrunk version of the constraint system.
    pub shrunk_cs: TurboCS<Fr>,
    /// The verifier parameters.
    pub verifier_params: PlonkVerifierParams<KZGCommitmentSchemeBN254>,
}

#[derive(Serialize, Deserialize)]
/// The prover parameters.
pub struct ProverParams {
    /// The full SRS for the polynomial commitment scheme.
    pub pcs: KZGCommitmentSchemeBN254,
    /// The Lagrange basis format of SRS.
    pub lagrange_pcs: Option<KZGCommitmentSchemeBN254>,
    /// The constraint system.
    pub cs: TurboCS<Fr>,
    /// The TurboPlonk proving key.
    pub prover_params: PlonkProverParams<KZGCommitmentSchemeBN254>,
}

impl ProverParams {
    /// Obtain the parameters for shuffle.
    pub fn gen_shuffle() -> Result<ProverParams, SetUpError> {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);
        let apk = EdwardsProjective::rand(&mut rng);
        let cards = [MaskedCard::rand(&mut rng); N_CARDS];
        let (cs, _) = build_cs(&mut rng, &apk, &cards);

        let cs_size = cs.size();
        let pcs = load_srs_params(cs_size)?;
        let lagrange_pcs = load_lagrange_params(cs_size);

        let verifier_params = if let Ok(v) = VerifierParams::load_shuffle() {
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
    pub fn refresh_public_key(&mut self, public_key: &EdwardsProjective) -> Result<(), SetUpError> {
        self.cs
            .load_shuffle_remark_parameters::<_, BabyJubjubShuffle>(public_key);

        let n = self.cs.size();
        let m = self.cs.quot_eval_dom_size();
        if m % n != 0 {
            return Err(SetUpError::ParameterError);
        }

        let pcs = load_srs_params(n)?;
        let lagrange_pcs = load_lagrange_params(n);
        let lagrange_pcs = lagrange_pcs.as_ref();
        let lagrange_pcs = if lagrange_pcs.is_some() && lagrange_pcs.unwrap().max_degree() + 1 == n
        {
            lagrange_pcs
        } else {
            None
        };

        let domain = FpPolynomial::evaluation_domain(n).ok_or(SetUpError::ParameterError)?;
        let domain_m =
            FpPolynomial::quotient_evaluation_domain(m).ok_or(SetUpError::ParameterError)?;

        let q_shuffle_public_key_evals = self.cs.compute_shuffle_public_key_selectors();

        let q_shuffle_public_key_polys: Vec<FpPolynomial<Fr>> = q_shuffle_public_key_evals
            .iter()
            .map(|p| FpPolynomial::ifft_with_domain(&domain, &p))
            .collect::<Vec<FpPolynomial<Fr>>>();

        let q_shuffle_public_key_coset_evals = q_shuffle_public_key_polys
            .iter()
            .map(|p| p.coset_fft_with_domain(&domain_m, &self.prover_params.verifier_params.k[1]))
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
                    .map_err(|_| SetUpError::ParameterError)?;
                cm_shuffle_public_key_vec.push(cm)
            } else {
                let cm = pcs
                    .commit(&q_shuffle_public_key_poly)
                    .map_err(|_| SetUpError::ParameterError)?;
                cm_shuffle_public_key_vec.push(cm)
            }
        }

        self.prover_params.q_shuffle_public_key_polys = q_shuffle_public_key_polys;
        self.prover_params.q_shuffle_public_key_coset_evals = q_shuffle_public_key_coset_evals;
        self.prover_params.verifier_params.cm_shuffle_public_key_vec = cm_shuffle_public_key_vec;

        Ok(())
    }
}

impl VerifierParams {
    /// Load the verifier parameters.
    pub fn get_shuffle() -> Result<VerifierParams, SetUpError> {
        match Self::load_shuffle() {
            Ok(vk) => Ok(vk),
            Err(_e) => Ok(Self::from(ProverParams::gen_shuffle()?)),
        }
    }

    /// Load the verifier parameters from prepare.
    pub fn load_shuffle() -> Result<VerifierParams, SetUpError> {
        match (VERIFIER_COMMON_PARAMS, VERIFIER_SPECIFIC_PARAMS) {
            (Some(c_bytes), Some(s_bytes)) => {
                let common: VerifierParamsSplitCommon =
                    bincode::deserialize(c_bytes).map_err(|_| SetUpError::DeserializationError)?;

                let special: VerifierParamsSplitSpecific =
                    bincode::deserialize(s_bytes).map_err(|_| SetUpError::DeserializationError)?;

                Ok(VerifierParams {
                    shrunk_vk: common.shrunk_pcs,
                    shrunk_cs: special.shrunk_cs,
                    verifier_params: special.verifier_params,
                })
            }
            _ => Err(SetUpError::MissingVerifierParamsError),
        }
    }

    /// Split the verifier parameters to the common part and the sspecific part.
    pub fn split(
        self,
    ) -> Result<(VerifierParamsSplitCommon, VerifierParamsSplitSpecific), SetUpError> {
        Ok((
            VerifierParamsSplitCommon {
                shrunk_pcs: self.shrunk_vk.shrink_to_verifier_only().unwrap(),
            },
            VerifierParamsSplitSpecific {
                shrunk_cs: self.shrunk_cs.shrink_to_verifier_only(),
                verifier_params: self.verifier_params,
            },
        ))
    }
}

impl From<ProverParams> for VerifierParams {
    fn from(params: ProverParams) -> Self {
        VerifierParams {
            shrunk_vk: params.pcs.shrink_to_verifier_only().unwrap(),
            shrunk_cs: params.cs.shrink_to_verifier_only(),
            verifier_params: params.prover_params.get_verifier_params(),
        }
    }
}

pub fn load_lagrange_params(size: usize) -> Option<KZGCommitmentSchemeBN254> {
    match LAGRANGE_BASES.get(&size) {
        None => None,
        Some(bytes) => KZGCommitmentSchemeBN254::from_unchecked_bytes(&bytes).ok(),
    }
}

pub fn load_srs_params(size: usize) -> Result<KZGCommitmentSchemeBN254, SetUpError> {
    let srs = SRS.ok_or(SetUpError::MissingSRSError)?;

    let KZGCommitmentSchemeBN254 {
        public_parameter_group_1,
        public_parameter_group_2,
    } = KZGCommitmentSchemeBN254::from_unchecked_bytes(&srs)
        .map_err(|_| SetUpError::DeserializationError)?;

    let mut new_group_1 = vec![G1Projective::default(); core::cmp::max(size + 3, 2051)];
    new_group_1[0..2051].copy_from_slice(&public_parameter_group_1[0..2051]);

    if size == 4096 {
        new_group_1[4096..4099].copy_from_slice(&public_parameter_group_1[2051..2054]);
    }

    if size == 8192 {
        new_group_1[8192..8195].copy_from_slice(&public_parameter_group_1[2054..2057]);
    }

    if size == 16384 {
        new_group_1[16384..16387].copy_from_slice(&public_parameter_group_1[2057..2060]);
    }

    if size > 16384 {
        return Err(SetUpError::ParameterError);
    }

    Ok(KZGCommitmentSchemeBN254 {
        public_parameter_group_2,
        public_parameter_group_1: new_group_1,
    })
}
