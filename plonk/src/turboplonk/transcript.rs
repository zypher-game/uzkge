use ark_ff::{BigInteger, PrimeField};

use crate::{poly_commit::pcs::PolyComScheme, utils::transcript::Transcript};

use super::indexer::PlonkVerifierParams;

/// Initialize the transcript when compute PLONK proof.
pub(crate) fn transcript_init_plonk<PCS: PolyComScheme>(
    transcript: &mut Transcript,
    params: &PlonkVerifierParams<PCS>,
    pi_values: &[PCS::Field],
    root: &PCS::Field,
) {
    transcript.append_message(b"New Domain", b"PLONK");

    transcript.append_u64(b"CS size", params.cs_size as u64);
    transcript.append_message(b"field size", &PCS::Field::MODULUS.to_bytes_be());
    for q in params.cm_q_vec.iter() {
        transcript.append_commitment(q);
    }
    for p in params.cm_s_vec.iter() {
        transcript.append_commitment(p);
    }
    transcript.append_challenge(root);
    for k in params.k.iter() {
        transcript.append_challenge(k);
    }
    for pi_value in pi_values.iter() {
        transcript.append_challenge(pi_value);
    }
}
