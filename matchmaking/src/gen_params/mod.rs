/// Definitions and constructions for prover and verifier parameters.
pub mod params;

pub use params::*;

#[cfg(not(feature = "no_vk"))]
/// The specific part of the verifier parameters.
pub static VERIFIER_SPECIFIC_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../../parameters/vk-specific.bin"));

#[cfg(feature = "no_vk")]
/// The specific part of the verifier parameters.
pub static VERIFIER_SPECIFIC_PARAMS: Option<&'static [u8]> = None;
