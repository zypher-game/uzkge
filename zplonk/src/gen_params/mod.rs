use ark_bn254::{Fr, G1Projective};
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::{collections::BTreeMap, One};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use crate::{
    errors::ZplonkError,
    poly_commit::field_polynomial::FpPolynomial,
    poly_commit::kzg_poly_commitment::KZGCommitmentSchemeBN254,
    poly_commit::pcs::PolyComScheme,
    turboplonk::constraint_system::ConstraintSystem,
    turboplonk::constraint_system::TurboCS,
    turboplonk::indexer::{PlonkProverParams, PlonkVerifierParams},
    utils::serialization::{point_to_uncompress_be, scalar_to_bytes_be},
};

#[cfg(not(feature = "no_vk"))]
/// The common part of the verifier parameters.
pub static VERIFIER_COMMON_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../../parameters/vk-common.bin"));

#[cfg(feature = "no_vk")]
/// The common part of the verifier parameters.
pub static VERIFIER_COMMON_PARAMS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_srs"))]
/// The SRS.
pub static SRS: Option<&'static [u8]> = Some(include_bytes!("../../parameters/srs-padding.bin"));

#[cfg(feature = "no_srs")]
/// The SRS.
pub static SRS: Option<&'static [u8]> = None;

#[cfg(feature = "no_srs")]
lazy_static! {
    /// The Lagrange format of the SRS.
    pub static ref LAGRANGE_BASES: BTreeMap<usize, &'static [u8]> = BTreeMap::default();
}

#[cfg(all(not(feature = "no_srs"), not(feature = "lightweight")))]
static LAGRANGE_BASE_4096: &'static [u8] = include_bytes!("../../parameters/lagrange-srs-4096.bin");

#[cfg(all(not(feature = "no_srs"), not(feature = "lightweight")))]
static LAGRANGE_BASE_8192: &'static [u8] = include_bytes!("../../parameters/lagrange-srs-8192.bin");

#[cfg(all(not(feature = "no_srs"), not(feature = "lightweight")))]
static LAGRANGE_BASE_16384: &'static [u8] =
    include_bytes!("../../parameters/lagrange-srs-16384.bin");

#[cfg(not(feature = "no_srs"))]
lazy_static! {
    /// The Lagrange format of the SRS.
    pub static ref LAGRANGE_BASES: BTreeMap<usize, &'static [u8]> = {
        let mut m = BTreeMap::new();
        #[cfg(not(feature = "lightweight"))]
        {
            m.insert(4096, LAGRANGE_BASE_4096);
            m.insert(8192, LAGRANGE_BASE_8192);
            m.insert(16384, LAGRANGE_BASE_16384);
        }

        m
    };
}

#[derive(Serialize, Deserialize, Debug)]
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

impl VerifierParams {
    /// Split the verifier parameters to the common part and the sspecific part.
    pub fn split(
        self,
    ) -> Result<(VerifierParamsSplitCommon, VerifierParamsSplitSpecific), ZplonkError> {
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

    //#[cfg(test)]
    pub fn pretty_print(&self) {
        let n = Fr::one().uncompressed_size() * 2;
        println!(
            "KZG pp1  : 0x{}",
            hex::encode(point_to_uncompress_be(
                &self.shrunk_vk.public_parameter_group_1[0]
            ))
        );
        // println!(
        //     "KZG pp2_0: {}",
        //     hex::encode(point_to_uncompress_be(
        //         &self.shrunk_vk.public_parameter_group_2[0].0
        //     ))
        // );
        // println!(
        //     "KZG pp2_1: {}",
        //     hex::encode(point_to_uncompress_be(
        //         &self.shrunk_vk.public_parameter_group_2[1].0
        //     ))
        // );
        println!("CS: vars: {}", self.shrunk_cs.num_vars);
        println!("CS: size: {}", self.shrunk_cs.size);
        for c in self.verifier_params.cm_q_vec.iter() {
            let s = hex::encode(point_to_uncompress_be(&c.0));
            println!("VP: cm selectors: 0x{}", &s[..n]);
            println!("VP: cm selectors: 0x{}", &s[n..]);
        }
        for c in self.verifier_params.cm_s_vec.iter() {
            let s = hex::encode(point_to_uncompress_be(&c.0));
            println!("VP: cm perm     : 0x{}", &s[..n]);
            println!("VP: cm perm     : 0x{}", &s[n..]);
        }

        let s = hex::encode(point_to_uncompress_be(&self.verifier_params.cm_qb.0));
        println!("VP: cm bool     : 0x{}", &s[..n]);
        println!("VP: cm bool     : 0x{}", &s[n..]);

        for c in self.verifier_params.cm_prk_vec.iter() {
            let s = hex::encode(point_to_uncompress_be(&c.0));
            println!("VP: cm prk      : 0x{}", &s[..n]);
            println!("VP: cm prk      : 0x{}", &s[n..]);
        }

        #[cfg(feature = "shuffle")]
        {
            let s = hex::encode(point_to_uncompress_be(&self.verifier_params.cm_q_ecc.0));
            println!("VP: cm ecc      : 0x{}", &s[..n]);
            println!("VP: cm ecc      : 0x{}", &s[n..]);
        }

        #[cfg(feature = "shuffle")]
        {
            for c in self.verifier_params.cm_shuffle_generator_vec.iter() {
                let s = hex::encode(point_to_uncompress_be(&c.0));
                println!("VP: cm shuffle  : 0x{}", &s[..n]);
                println!("VP: cm shuffle  : 0x{}", &s[n..]);
            }
        }

        let s = hex::encode(scalar_to_bytes_be(&self.verifier_params.anemoi_generator));
        println!("VP: anemoi g    : 0x{}", s);

        let s = hex::encode(scalar_to_bytes_be(
            &self.verifier_params.anemoi_generator_inv,
        ));
        println!("VP: anemoi g inv: 0x{}", s);

        for c in self.verifier_params.k.iter() {
            let s = hex::encode(scalar_to_bytes_be(c));
            println!("VP: wires  (k)  : 0x{}", s);
        }

        #[cfg(feature = "shuffle")]
        {
            let s = hex::encode(scalar_to_bytes_be(&self.verifier_params.edwards_a));
            println!("VP: edwards_a   : 0x{}", s);
        }

        println!("VP: cs size     : {}", self.verifier_params.cs_size);

        println!(
            "VP: pi size     : {}",
            self.verifier_params.public_vars_constraint_indices.len()
        );

        let domain = FpPolynomial::<Fr>::evaluation_domain(self.verifier_params.cs_size).unwrap();
        let root = domain.group_gen;
        let s = hex::encode(scalar_to_bytes_be(&root));
        println!("VP: group gen   : 0x{}", s);

        for (i, c) in self
            .verifier_params
            .public_vars_constraint_indices
            .iter()
            .enumerate()
        {
            let p = root.pow(&[*c as u64]);
            let s = hex::encode(scalar_to_bytes_be(&p));
            println!("PI_POLY_INDICES_LOC[{}] = 0x{};", i, s);
        }

        for (i, c) in self.verifier_params.lagrange_constants.iter().enumerate() {
            let s = hex::encode(scalar_to_bytes_be(c));
            println!("PI_POLY_LAGRANGE_LOC[{}] = 0x{};", i, s);
        }
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

pub fn load_srs_params(size: usize) -> Result<KZGCommitmentSchemeBN254, ZplonkError> {
    let srs = SRS.ok_or(ZplonkError::MissingSRSError)?;

    let KZGCommitmentSchemeBN254 {
        public_parameter_group_1,
        public_parameter_group_2,
    } = KZGCommitmentSchemeBN254::from_unchecked_bytes(&srs)
        .map_err(|_| ZplonkError::DeserializationError)?;

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
        return Err(ZplonkError::ParameterError);
    }

    Ok(KZGCommitmentSchemeBN254 {
        public_parameter_group_2,
        public_parameter_group_1: new_group_1,
    })
}
