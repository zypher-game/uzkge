/// Definitions and constructions for prover and verifier parameters.
pub mod params;

pub use params::*;

use std::sync::Mutex;

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

#[cfg(not(feature = "no_srs"))]
lazy_static! {
    pub static ref PROVER_PARAMS: Mutex<ProverParams> =
        Mutex::new(gen_shuffle_prover_params().unwrap());
}
