use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_std::{
    ops::Mul,
    rand::{CryptoRng, RngCore},
    UniformRand,
};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{Result, ZplonkError},
    poly_commit::pcs::ToBytes,
    utils::{
        serialization::{ark_deserialize, ark_serialize},
        transcript::Transcript,
    },
};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct ChaumPedersenDLParameters {
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub g: EdwardsProjective,
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub h: EdwardsProjective,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct ChaumPedersenDLProof {
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub a: EdwardsProjective,
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub b: EdwardsProjective,
    #[serde(serialize_with = "ark_serialize", deserialize_with = "ark_deserialize")]
    pub r: Fr,
}

impl ChaumPedersenDLProof {
    pub fn to_uncompress(&self) -> Vec<u8> {
        let mut bytes = vec![];

        let aa = EdwardsAffine::from(self.a);
        bytes.extend(aa.x.into_bigint().to_bytes_be());
        bytes.extend(aa.y.into_bigint().to_bytes_be());

        let ab = EdwardsAffine::from(self.b);
        bytes.extend(ab.x.into_bigint().to_bytes_be());
        bytes.extend(ab.y.into_bigint().to_bytes_be());

        bytes.extend(self.r.into_bigint().to_bytes_be());

        bytes
    }

    pub fn from_uncompress(bytes: &[u8]) -> core::result::Result<Self, ZplonkError> {
        if bytes.len() < 160 {
            return Err(ZplonkError::SerializationError);
        }

        let ax = Fq::from_be_bytes_mod_order(&bytes[..32]);
        let ay = Fq::from_be_bytes_mod_order(&bytes[32..64]);
        let a = EdwardsAffine::new(ax, ay).into();

        let bx = Fq::from_be_bytes_mod_order(&bytes[64..96]);
        let by = Fq::from_be_bytes_mod_order(&bytes[96..128]);
        let b = EdwardsAffine::new(bx, by).into();

        let r = Fr::from_be_bytes_mod_order(&bytes[128..160]);

        Ok(Self { a, b, r })
    }
}

pub fn prove<R: CryptoRng + RngCore>(
    prng: &mut R,
    parameters: &ChaumPedersenDLParameters,
    transcript: &mut Transcript,
    witness: &Fr,
    c1: &EdwardsProjective,
    c2: &EdwardsProjective,
) -> Result<ChaumPedersenDLProof> {
    let new_c1 = parameters.g.mul(witness);
    let new_c2 = parameters.h.mul(witness);
    assert_eq!(new_c1, *c1);
    assert_eq!(new_c2, *c2);

    // 1. init transcript
    transcript.append_message(b"Chaum Pedersen", b"DL");
    transcript.append_message(b"append commitment", &parameters.g.to_transcript_bytes());
    transcript.append_message(b"append commitment", &parameters.h.to_transcript_bytes());
    transcript.append_message(b"append commitment", &c1.to_transcript_bytes());
    transcript.append_message(b"append commitment", &c2.to_transcript_bytes());

    // 2. random a omega
    let omega = Fr::rand(prng);

    let a = parameters.g.mul(&omega);
    let b = parameters.h.mul(&omega);

    transcript.append_message(b"append commitment", &a.to_transcript_bytes());
    transcript.append_message(b"append commitment", &b.to_transcript_bytes());

    let c: Fr = transcript.get_challenge_field_elem(b"Chaum Pedersen C");

    let r = omega + c * witness;

    Ok(ChaumPedersenDLProof { a, b, r })
}

pub fn verify(
    parameters: &ChaumPedersenDLParameters,
    transcript: &mut Transcript,
    c1: &EdwardsProjective,
    c2: &EdwardsProjective,
    proof: &ChaumPedersenDLProof,
) -> Result<()> {
    // init transcript
    transcript.append_message(b"Chaum Pedersen", b"DL");
    transcript.append_message(b"append commitment", &parameters.g.to_transcript_bytes());
    transcript.append_message(b"append commitment", &parameters.h.to_transcript_bytes());
    transcript.append_message(b"append commitment", &c1.to_transcript_bytes());
    transcript.append_message(b"append commitment", &c2.to_transcript_bytes());

    transcript.append_message(b"append commitment", &proof.a.to_transcript_bytes());
    transcript.append_message(b"append commitment", &proof.b.to_transcript_bytes());

    let c: Fr = transcript.get_challenge_field_elem(b"Chaum Pedersen C");

    if parameters.g.mul(&proof.r) != proof.a + c1.mul(&c) {
        return Err(ZplonkError::VerificationError);
    }

    if parameters.h.mul(&proof.r) != proof.b + c2.mul(&c) {
        return Err(ZplonkError::VerificationError);
    }

    Ok(())
}
