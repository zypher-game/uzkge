use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fq};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{Compress, Validate};
use rand_chacha::{
    rand_core::{CryptoRng, RngCore, SeedableRng},
    ChaChaRng,
};
use serde::{Deserialize, Serialize};
use uzkge::{
    plonk::{constraint_system::TurboCS, indexer::PlonkProof},
    poly_commit::kzg_poly_commitment::KZGCommitmentSchemeBN254,
    errors::UzkgeError,
};
use crate::error::{ShuffleError};

pub fn default_prng() -> impl RngCore + CryptoRng {
    ChaChaRng::from_entropy()
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct BigNumber {
    _isBigNumber: bool,
    _hex: String,
}

pub fn hex_to_scalar<F: PrimeField>(hex: &str) -> Result<F, ShuffleError> {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex)?;
    if bytes.len() != 32 {
        return Err(ShuffleError::DecodeError("Bytes length not 32".to_owned()));
    }
    Ok(F::from_be_bytes_mod_order(&bytes))
}

pub fn scalar_to_hex<F: PrimeField>(scalar: &F, with_start: bool) -> String {
    let bytes = scalar.into_bigint().to_bytes_be();
    let s = hex::encode(&bytes);
    if with_start {
        format!("0x{}", s)
    } else {
        s
    }
}

pub fn hex_to_point<G: CurveGroup>(hex: &str) -> Result<G, ShuffleError> {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex)?;
    Ok(G::deserialize_with_mode(bytes.as_slice(), Compress::Yes, Validate::Yes).map_err(|_| ShuffleError::UzkgeError(UzkgeError::DeserializationError))?)
}

pub fn point_to_hex<G: CurveGroup>(point: &G, with_start: bool) -> String {
    let mut bytes = Vec::new();
    point
        .serialize_with_mode(&mut bytes, Compress::Yes)
        .unwrap();
    let s = hex::encode(&bytes);
    if with_start {
        format!("0x{}", s)
    } else {
        s
    }
}

pub fn point_to_uncompress<F: PrimeField, G: CurveGroup<BaseField = F>>(
    point: &G,
    with_start: bool,
) -> (String, String) {
    let affine = G::Affine::from(*point);
    let (x, y) = affine.xy().unwrap();
    let x_bytes = x.into_bigint().to_bytes_be();
    let y_bytes = y.into_bigint().to_bytes_be();
    let x = hex::encode(&x_bytes);
    let y = hex::encode(&y_bytes);

    if with_start {
        (format!("0x{}", x), format!("0x{}", y))
    } else {
        (x, y)
    }
}

pub fn uncompress_to_point(x_str: &str, y_str: &str) -> Result<EdwardsProjective, ShuffleError> {
    let x_hex = x_str.trim_start_matches("0x");
    let y_hex = y_str.trim_start_matches("0x");
    let x_bytes = hex::decode(x_hex)?;
    let y_bytes = hex::decode(y_hex)?;

    let x = Fq::from_be_bytes_mod_order(&x_bytes);
    let y = Fq::from_be_bytes_mod_order(&y_bytes);
    let affine = EdwardsAffine::new(x, y);

    Ok(affine.into())
}

pub fn shuffle_proof_from_hex(s: &str) -> Result<PlonkProof<KZGCommitmentSchemeBN254>, ShuffleError> {
    let hex = s.trim_start_matches("0x");
    let bytes = hex::decode(hex)?;
    Ok(PlonkProof::<KZGCommitmentSchemeBN254>::from_bytes_be::<TurboCS<Fr>>(&bytes).map_err(|e| ShuffleError::UzkgeError(e))?)
}

pub fn shuffle_proof_to_hex(proof: &PlonkProof<KZGCommitmentSchemeBN254>) -> String {
    let bytes = proof.to_bytes_be();
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
pub mod tests{
    use super::*;
    use crate::error::ShuffleResult;
    use crate::sdk::Keypair;
    use crate::keygen::Keypair as CoreKeypair;
    pub fn generate_key_preset(sk : String, pk: String, x : String,y: String) -> ShuffleResult<Keypair> {
        let mut prng = default_prng();
        let keypair = CoreKeypair::generate(&mut prng);
        let _pkxy = point_to_uncompress(&keypair.public, true);

        let ret = Keypair {
            sk: sk,
            pk: pk,
            pkxy: (x,y),
        };

        Ok(ret)
    }
}