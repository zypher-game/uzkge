use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

use crate::errors::ZplonkError;

pub fn to_bytes<A: CanonicalSerialize>(a: &A) -> Vec<u8> {
    let mut bytes = vec![];
    let _ = a.serialize_with_mode(&mut bytes, Compress::Yes);
    bytes
}

pub fn from_bytes<A: Default + CanonicalSerialize + CanonicalDeserialize>(
    bytes: &[u8],
) -> Result<A, ZplonkError> {
    let n = A::default().serialized_size(Compress::Yes);
    let mut new_bytes = vec![0u8; n];
    let m = core::cmp::min(n, bytes.len());
    new_bytes[..m].copy_from_slice(&bytes[..m]);

    A::deserialize_with_mode(new_bytes.as_slice(), Compress::Yes, Validate::Yes)
        .map_err(|_| ZplonkError::SerializationError)
}

pub fn ark_serialize<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_bytes(&to_bytes(a))
}

pub fn ark_deserialize<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::Yes)
        .map_err(serde::de::Error::custom)
}

#[inline]
pub fn point_to_uncompress_be<F: PrimeField, G: CurveGroup<BaseField = F>>(p: &G) -> Vec<u8> {
    let affine = G::Affine::from(*p);
    let (x, y) = affine.xy().unwrap_or((F::zero(), F::zero()));
    let mut x_bytes = scalar_to_bytes_be(&x);
    let y_bytes = scalar_to_bytes_be(&y);
    x_bytes.extend(y_bytes);
    x_bytes
}

#[inline]
pub fn point_from_uncompress_be<G: CurveGroup>(
    bytes: &[u8],
    len_check: bool,
) -> Result<G, ZplonkError> {
    let (mut x_bytes_be, mut y_bytes_be) = if len_check {
        let m = G::generator().uncompressed_size();
        if bytes.len() < m || m % 2 != 0 {
            return Err(ZplonkError::DeserializationError);
        }
        (bytes[0..m / 2].to_vec(), bytes[m / 2..].to_vec())
    } else {
        let n = bytes.len() / 2;
        (bytes[0..n].to_vec(), bytes[n..].to_vec())
    };
    x_bytes_be.reverse();
    y_bytes_be.reverse();
    x_bytes_be.extend(y_bytes_be);

    G::deserialize_with_mode(x_bytes_be.as_slice(), Compress::No, Validate::Yes)
        .map_err(|_| ZplonkError::DeserializationError)
}

#[inline]
pub fn scalar_to_bytes_be<F: PrimeField>(scalar: &F) -> Vec<u8> {
    scalar.into_bigint().to_bytes_be()
}

#[inline]
pub fn scalar_from_bytes_be<F: PrimeField>(
    bytes: &[u8],
    len_check: bool,
) -> Result<F, ZplonkError> {
    let checked_bytes = if len_check {
        let n = F::one().uncompressed_size();
        if bytes.len() < n {
            return Err(ZplonkError::DeserializationError);
        }
        &bytes[..n]
    } else {
        bytes
    };
    Ok(F::from_be_bytes_mod_order(checked_bytes))
}
