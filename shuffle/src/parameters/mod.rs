/// Definitions and constructions for prover and verifier parameters.
pub mod errors;
pub mod params;

use std::sync::Mutex;

pub use params::*;

use ark_std::collections::BTreeMap;

#[cfg(not(feature = "no_srs"))]
/// The SRS.
pub static SRS: Option<&'static [u8]> = Some(include_bytes!("../../parameters/srs-padding.bin"));

#[cfg(feature = "no_srs")]
/// The SRS.
pub static SRS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
/// The common part of the verifier parameters.
pub static VERIFIER_COMMON_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../../parameters/vk-common.bin"));

#[cfg(feature = "no_vk")]
/// The common part of the verifier parameters.
pub static VERIFIER_COMMON_PARAMS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
/// The specific part of the verifier parameters.
pub static VERIFIER_SPECIFIC_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../../parameters/vk-specific.bin"));

#[cfg(feature = "no_vk")]
/// The specific part of the verifier parameters.
pub static VERIFIER_SPECIFIC_PARAMS: Option<&'static [u8]> = None;

#[cfg(feature = "no_srs")]
lazy_static! {
    /// The Lagrange format of the SRS.
    pub static ref LAGRANGE_BASES: BTreeMap<usize, &'static [u8]> = BTreeMap::default();
}

#[cfg(all(not(feature = "no_srs"), not(feature = "lightweight")))]
static LAGRANGE_BASE_16384: &'static [u8] =
    include_bytes!("../../parameters/lagrange-srs-16384.bin");

#[cfg(not(feature = "no_srs"))]
lazy_static! {
    /// The Lagrange format of the SRS.
    pub static ref LAGRANGE_BASES: BTreeMap<usize, &'static [u8]> = {
        let mut m = BTreeMap::new();
        m.insert(16384,LAGRANGE_BASE_16384);
        m
    };

    pub static ref PROVER_PARAMS: Mutex<ProverParams> =
    Mutex::new(ProverParams::gen_shuffle().unwrap());
}
