use crate::errors::ZplonkError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

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
