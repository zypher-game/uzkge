/// Definitions and constructions for prover and verifier parameters.
pub mod params;

pub use params::*;

#[cfg(not(feature = "no_vk"))]
/// The common part of the verifier parameters.
pub static VERIFIER_COMMON_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../../parameters/vk-common.bin"));

#[cfg(feature = "no_vk")]
/// The common part of the verifier parameters.
pub static VERIFIER_COMMON_PARAMS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
/// The specific part of the verifier parameters.
pub static VERIFIER_SPECIFIC_PARAMS_52: Option<&'static [u8]> =
    Some(include_bytes!("../../parameters/vk-specific-52.bin"));

#[cfg(feature = "no_vk")]
/// The specific part of the verifier parameters.
pub static VERIFIER_SPECIFIC_PARAMS_52: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
/// The specific part of the verifier parameters.
pub static VERIFIER_SPECIFIC_PARAMS_54: Option<&'static [u8]> =
    Some(include_bytes!("../../parameters/vk-specific-54.bin"));

#[cfg(feature = "no_vk")]
/// The specific part of the verifier parameters.
pub static VERIFIER_SPECIFIC_PARAMS_54: Option<&'static [u8]> = None;
