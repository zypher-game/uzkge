use alloc::vec::Vec;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fq};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use core::slice;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use uzkge::gen_params::VerifierParams;
use zshuffle::{
    build_cs::{prove_shuffle, verify_shuffle, ShuffleProof, TurboCS},
    gen_params::{
        gen_shuffle_prover_params, get_shuffle_verifier_params, refresh_prover_params_public_key,
    },
    keygen::PublicKey,
    MaskedCard,
};

use crate::Bytes;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CardParam {
    x1: Bytes,
    y1: Bytes,
    x2: Bytes,
    y2: Bytes,
}
fn bytes_2_masked_card(card: &CardParam) -> Option<MaskedCard> {
    let e1: EdwardsProjective = {
        let x = Fq::from_be_bytes_mod_order(card.x1.to_slice());
        let y = Fq::from_be_bytes_mod_order(card.y1.to_slice());
        let affine = EdwardsAffine::new(x, y);
        affine.into()
    };

    let e2: EdwardsProjective = {
        let x = Fq::from_be_bytes_mod_order(card.x2.to_slice());
        let y = Fq::from_be_bytes_mod_order(card.y2.to_slice());
        let affine = EdwardsAffine::new(x, y);
        affine.into()
    };
    Some(MaskedCard { e1, e2 })
}

pub fn point_to_uncompress<F: PrimeField, G: CurveGroup<BaseField = F>>(
    point: &G,
) -> (Vec<u8>, Vec<u8>) {
    let affine = G::Affine::from(*point);
    let (x, y) = affine.xy().unwrap();
    (x.into_bigint().to_bytes_be(), y.into_bigint().to_bytes_be())
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __generate_shuffle_proof(
    rng_seed: Bytes,
    pk: Bytes,
    inputs_param: *const CardParam,
    inputs_len: u32,
    n_cards: u32,
    out_verifier_params: *mut u8,
    out_verifier_params_len: *mut u32,
    out_outputs: *mut u8,
    out_outputs_len: *mut u32,
    out_proof: *mut u8,
    out_proof_len: *mut u32,
) -> i32 {
    let inputs_cards = {
        let mut inputs = Vec::new();
        for i in 0..inputs_len as usize {
            let cards = unsafe { *inputs_param.wrapping_add(i) };

            match bytes_2_masked_card(&cards) {
                Some(v) => inputs.push(v),
                None => return -2,
            }
        }
        inputs
    };
    let pk = match PublicKey::deserialize_with_mode(pk.to_slice(), Compress::Yes, Validate::Yes) {
        Ok(v) => v,
        Err(_) => return -3,
    };

    let seed = match rng_seed.to_slice().try_into() {
        Ok(v) => v,
        Err(_e) => return -4,
    };
    let mut rng = ChaChaRng::from_seed(seed);

    let mut prover_params = match gen_shuffle_prover_params(n_cards as usize) {
        Ok(v) => v,
        Err(_e) => return -5,
    };

    if let Err(_e) = refresh_prover_params_public_key(&mut prover_params, &pk) {
        return -6;
    }

    let mut verifier_params = match get_shuffle_verifier_params(n_cards as usize) {
        Ok(v) => v,
        Err(_e) => return -7,
    };
    verifier_params.verifier_params = prover_params.prover_params.verifier_params.clone();

    // Alice, start shuffling.
    let (proof, outputs_cards) = match prove_shuffle(&mut rng, &pk, &inputs_cards, &prover_params) {
        Ok(v) => v,
        Err(_e) => return -8,
    };

    let proof = proof.to_bytes_be();

    let verifier_params = match bincode::serialize(&verifier_params) {
        Ok(v) => v,
        Err(_e) => return -9,
    };

    if unsafe { *out_verifier_params_len } < verifier_params.len() as u32 {
        return -10;
    }
    let out_verifier_params = unsafe {
        slice::from_raw_parts_mut(out_verifier_params, (*out_verifier_params_len) as usize)
    };
    out_verifier_params[..verifier_params.len()].copy_from_slice(&verifier_params);
    unsafe { *out_verifier_params_len = verifier_params.len() as u32 };

    if unsafe { (*out_outputs_len) * 4 * 32 } < (outputs_cards.len() * 4 * 32) as u32 {
        return -11;
    }

    let out_outputs =
        unsafe { slice::from_raw_parts_mut(out_outputs, ((*out_outputs_len) * 4 * 32) as usize) };

    for (index, outputs) in outputs_cards.iter().enumerate() {
        let (x, y) = point_to_uncompress(&outputs.e1);
        out_outputs[index * 128..index * 128 + 32].copy_from_slice(&x);
        out_outputs[index * 128 + 32..index * 128 + 64].copy_from_slice(&y);

        let (x, y) = point_to_uncompress(&outputs.e2);
        out_outputs[index * 128 + 64..index * 128 + 96].copy_from_slice(&x);
        out_outputs[index * 128 + 96..index * 128 + 128].copy_from_slice(&y);
    }
    unsafe { *out_outputs_len = outputs_cards.len() as u32 };

    if unsafe { *out_proof_len } < proof.len() as u32 {
        return -12;
    }
    let out_proof = unsafe { slice::from_raw_parts_mut(out_proof, (*out_proof_len) as usize) };
    out_proof[..proof.len()].copy_from_slice(&proof);
    unsafe { *out_proof_len = proof.len() as u32 };

    0
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __verify_shuffle(
    verifier_params: Bytes,
    inputs_param: *const CardParam,
    inputs_len: u32,
    outputs_param: *const CardParam,
    outputs_len: u32,
    proof: Bytes,
) -> i32 {
    let verifier_params: VerifierParams = {
        let data =
            unsafe { slice::from_raw_parts(verifier_params.data, verifier_params.len as usize) };
        match bincode::deserialize(data) {
            Ok(v) => v,
            Err(_e) => return -1,
        }
    };

    let inputs_cards = {
        let mut inputs = Vec::new();
        for i in 0..inputs_len as usize {
            let cards = unsafe { *inputs_param.wrapping_add(i) };

            match bytes_2_masked_card(&cards) {
                Some(v) => inputs.push(v),
                None => return -1,
            }
        }
        inputs
    };

    let outputs_cards = {
        let mut outputs = Vec::new();
        for i in 0..outputs_len as usize {
            let cards = unsafe { *outputs_param.wrapping_add(i) };

            match bytes_2_masked_card(&cards) {
                Some(v) => outputs.push(v),
                None => return -2,
            }
        }
        outputs
    };

    let proof: ShuffleProof = match ShuffleProof::from_bytes_be::<TurboCS>(proof.to_slice()) {
        Ok(v) => v,
        Err(_e) => return -3,
    };

    match verify_shuffle(&verifier_params, &inputs_cards, &outputs_cards, &proof) {
        Ok(_) => 0,
        Err(_e) => -4,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloc::vec::Vec;
    use ark_ff::{One, UniformRand};
    use rand_chacha::{
        rand_core::{CryptoRng, RngCore, SeedableRng},
        ChaChaRng,
    };

    use uzkge::poly_commit::pcs::ToBytes;
    use zshuffle::{
        keygen::{aggregate_keys, Keypair},
        mask::{mask, verify_mask},
        Card,
    };

    use crate::{
        shuffle::{point_to_uncompress, CardParam},
        Bytes,
    };

    use super::{__generate_shuffle_proof, __verify_shuffle};

    #[derive(PartialEq, PartialOrd, Clone, Copy, Eq)]
    pub enum Value {
        Two,
        Three,
        Four,
        Five,
        Six,
        Seven,
        Eight,
        Nine,
        Ten,
        Jack,
        Queen,
        King,
        Ace,
    }

    impl Value {
        const VALUES: [Self; 13] = [
            Self::Two,
            Self::Three,
            Self::Four,
            Self::Five,
            Self::Six,
            Self::Seven,
            Self::Eight,
            Self::Nine,
            Self::Ten,
            Self::Jack,
            Self::Queen,
            Self::King,
            Self::Ace,
        ];
    }

    #[derive(PartialEq, Clone, Copy, Eq)]
    pub enum Suite {
        Club,
        Diamond,
        Heart,
        Spade,
    }

    impl Suite {
        const SUITES: [Self; 4] = [Self::Club, Self::Diamond, Self::Heart, Self::Spade];
    }

    #[derive(PartialEq, Clone, Eq, Copy)]
    pub struct ClassicPlayingCard {
        value: Value,
        suite: Suite,
    }

    pub struct Cards {
        x1: Vec<u8>,
        y1: Vec<u8>,
        x2: Vec<u8>,
        y2: Vec<u8>,
    }

    impl ClassicPlayingCard {
        pub fn new(value: Value, suite: Suite) -> Self {
            Self { value, suite }
        }
    }

    fn encode_cards<R: CryptoRng + RngCore>(rng: &mut R) -> HashMap<Card, ClassicPlayingCard> {
        let num_of_cards = Value::VALUES.len() * Suite::SUITES.len();
        let mut map: HashMap<Card, ClassicPlayingCard> = HashMap::new();
        let plaintexts = (0..num_of_cards)
            .map(|_| Card::rand(rng))
            .collect::<Vec<_>>();

        let mut i = 0;
        for value in Value::VALUES.iter().copied() {
            for suite in Suite::SUITES.iter().copied() {
                let current_card = ClassicPlayingCard::new(value, suite);
                map.insert(plaintexts[i], current_card);
                i += 1;
            }
        }

        map
    }
    #[test]
    fn test() {
        let rng_seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(rng_seed);

        let card_mapping = encode_cards(&mut rng);

        let keys = [Keypair::generate(&mut rng).public].to_vec();
        let joint_pk = aggregate_keys(&keys).unwrap();
        let pk = joint_pk.to_bytes();

        let mut deck = Vec::new();
        for card in card_mapping.keys() {
            let (masked_card, masked_proof) =
                mask(&mut rng, &joint_pk, card, &ark_ed_on_bn254::Fr::one()).unwrap();
            verify_mask(&joint_pk, card, &masked_card, &masked_proof).unwrap();

            deck.push(masked_card)
        }

        let deck = {
            let mut ret = Vec::new();
            for it in deck.iter() {
                let (x1, y1) = point_to_uncompress(&it.e1);

                let (x2, y2) = point_to_uncompress(&it.e2);

                ret.push(Cards { x1, y1, x2, y2 })
            }
            ret
        };

        let mut inputs = Vec::new();
        for input in deck.iter() {
            inputs.push(CardParam {
                x1: Bytes {
                    len: input.x1.len() as u32,
                    data: input.x1.as_ptr(),
                },
                y1: Bytes {
                    len: input.y1.len() as u32,
                    data: input.y1.as_ptr(),
                },
                x2: Bytes {
                    len: input.x2.len() as u32,
                    data: input.x2.as_ptr(),
                },
                y2: Bytes {
                    len: input.y2.len() as u32,
                    data: input.y2.as_ptr(),
                },
            });
        }

        let mut out_verifier_params = [0u8; 102400];
        let mut out_verifier_params_len = out_verifier_params.len() as u32;

        let mut out_outputs = [0u8; 60 * 4 * 32];
        let mut out_outputs_len = 60;

        let mut out_proof = [0u8; 20480];
        let mut out_proof_len = out_proof.len() as u32;

        let res = __generate_shuffle_proof(
            Bytes {
                len: rng_seed.len() as u32,
                data: rng_seed.as_ptr(),
            },
            Bytes {
                len: pk.len() as u32,
                data: pk.as_ptr(),
            },
            inputs.as_ptr(),
            inputs.len() as u32,
            52,
            out_verifier_params.as_mut_ptr(),
            &mut out_verifier_params_len,
            out_outputs.as_mut_ptr(),
            &mut out_outputs_len,
            out_proof.as_mut_ptr(),
            &mut out_proof_len,
        );
        assert_eq!(res, 0);

        let mut outputs = Vec::new();
        for i in 0..out_outputs_len as usize {
            outputs.push(CardParam {
                x1: Bytes {
                    len: 32,
                    data: unsafe { out_outputs.as_ptr().byte_add(i * 128) },
                },
                y1: Bytes {
                    len: 32,
                    data: unsafe { out_outputs.as_ptr().byte_add(i * 128 + 32) },
                },
                x2: Bytes {
                    len: 32,
                    data: unsafe { out_outputs.as_ptr().byte_add(i * 128 + 64) },
                },
                y2: Bytes {
                    len: 32,
                    data: unsafe { out_outputs.as_ptr().byte_add(i * 128 + 96) },
                },
            });
        }

        let res = __verify_shuffle(
            Bytes {
                len: out_verifier_params_len,
                data: out_verifier_params.as_ptr(),
            },
            inputs.as_ptr(),
            inputs.len() as u32,
            outputs.as_ptr(),
            out_outputs_len,
            Bytes {
                len: out_proof_len,
                data: out_proof.as_ptr(),
            },
        );
        assert_eq!(res, 0);
    }
}
