use ark_ec::PrimeGroup;
use ark_ed_on_bn254::{EdwardsProjective, Fr};
use ark_ff::UniformRand;
use ark_std::rand::{CryptoRng, RngCore};
use zplonk::errors::Result;

pub type PublicKey = EdwardsProjective;

pub type SecretKey = Fr;

pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    pub fn from_secret(secret: SecretKey) -> Self {
        let public = EdwardsProjective::generator() * secret;
        Keypair { secret, public }
    }

    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let secret = Fr::rand(prng);
        Self::from_secret(secret)
    }
}

pub fn aggregate_keys(keys: &[PublicKey]) -> Result<PublicKey> {
    Ok(keys.iter().sum())
}
