use alloc::{format, string::String, vec::Vec};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fq};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use serde::{Deserialize, Serialize};
use uzkge::gen_params::VerifierParams;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zshuffle::{
    build_cs::{prove_shuffle, verify_shuffle, ShuffleProof, TurboCS},
    gen_params::{
        gen_shuffle_prover_params, get_shuffle_verifier_params, refresh_prover_params_public_key,
    },
    keygen::PublicKey,
    MaskedCard,
};

fn bytes_2_masked_card(cards: &[Vec<u8>]) -> Option<MaskedCard> {
    let e1: EdwardsProjective = {
        let x = Fq::from_be_bytes_mod_order(cards.first()?);
        let y = Fq::from_be_bytes_mod_order(cards.get(1)?);
        let affine = EdwardsAffine::new(x, y);
        affine.into()
    };

    let e2: EdwardsProjective = {
        let x = Fq::from_be_bytes_mod_order(cards.get(2)?);
        let y = Fq::from_be_bytes_mod_order(cards.get(3)?);
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

#[derive(Serialize, Deserialize)]
struct ShuffleProofReturn {
    verifier_params: String,
    outputs: Vec<Vec<String>>,
    proof: String,
}

#[wasm_bindgen]
pub fn generate_shuffle_proof(
    rng_seed: String,
    pk: String,
    inputs: Vec<JsValue>,
    n_cards: u32,
) -> JsValue {
    let rng_seed = {
        hex::decode(rng_seed.strip_prefix("0x").unwrap_or(&rng_seed))
            .expect("hex decode rng_seed error")
            .try_into()
            .unwrap()
    };
    let mut rng = ChaChaRng::from_seed(rng_seed);

    let pk = {
        let pk = hex::decode(pk.strip_prefix("0x").unwrap_or(&pk)).unwrap();
        PublicKey::deserialize_with_mode(&pk[..], Compress::Yes, Validate::Yes).unwrap()
    };

    let mut inputs_cards = Vec::new();
    for (i, cards) in inputs.iter().enumerate() {
        let cards: Vec<String> = serde_wasm_bindgen::from_value(cards.clone()).unwrap();
        let mut card_param = Vec::new();
        for (j, card) in cards.iter().enumerate() {
            let data = hex::decode(card.strip_prefix("0x").unwrap_or(&card))
                .expect(&format!("hex decode {} {} input error", i, j));
            card_param.push(data)
        }
        let input =
            bytes_2_masked_card(&card_param).expect(&format!("hex decode {} input error", i));
        inputs_cards.push(input)
    }

    let mut prover_params = gen_shuffle_prover_params(n_cards as usize).unwrap();

    refresh_prover_params_public_key(&mut prover_params, &pk).unwrap();

    let mut verifier_params = get_shuffle_verifier_params(n_cards as usize).unwrap();
    verifier_params.verifier_params = prover_params.prover_params.verifier_params.clone();

    // Alice, start shuffling.
    let (proof, output_cards) =
        prove_shuffle(&mut rng, &pk, &inputs_cards, &prover_params).unwrap();

    let proof = proof.to_bytes_be();

    let verifier_params = bincode::serialize(&verifier_params).unwrap();

    let alice_shuffle_deck = {
        let mut ret = Vec::new();
        for it in output_cards.iter() {
            let mut tmp = Vec::new();

            let (x, y) = point_to_uncompress(&it.e1);
            tmp.push(format!("0x{}", hex::encode(x)));
            tmp.push(format!("0x{}", hex::encode(y)));

            let (x, y) = point_to_uncompress(&it.e2);
            tmp.push(format!("0x{}", hex::encode(x)));
            tmp.push(format!("0x{}", hex::encode(y)));
            ret.push(tmp)
        }
        ret
    };
    let ret = ShuffleProofReturn {
        verifier_params: format!("0x{}", hex::encode(verifier_params)),
        outputs: alice_shuffle_deck,
        proof: format!("0x{}", hex::encode(proof)),
    };
    serde_wasm_bindgen::to_value(&ret).unwrap()
}

#[wasm_bindgen]
pub fn plonk_verify_shuffle(
    verifier_params: String,
    inputs: Vec<JsValue>,
    outputs: Vec<JsValue>,
    proof: String,
) -> bool {
    let verifier_params: VerifierParams = {
        let data = hex::decode(
            verifier_params
                .strip_prefix("0x")
                .unwrap_or(&verifier_params),
        )
        .expect("hex decode verifier_params error");
        bincode::deserialize(&data).expect("bincode deserialize verifier_params error")
    };

    let mut input_param = Vec::new();
    for (i, cards) in inputs.iter().enumerate() {
        let cards: Vec<String> = serde_wasm_bindgen::from_value(cards.clone()).unwrap();
        let mut card_param = Vec::new();
        for (j, card) in cards.iter().enumerate() {
            let data = hex::decode(card.strip_prefix("0x").unwrap_or(&card))
                .expect(&format!("hex decode {} {} input error", i, j));
            card_param.push(data)
        }
        let input =
            bytes_2_masked_card(&card_param).expect(&format!("hex decode {} input error", i));
        input_param.push(input)
    }

    let mut output_param = Vec::new();
    for (i, cards) in outputs.iter().enumerate() {
        let cards: Vec<String> = serde_wasm_bindgen::from_value(cards.clone()).unwrap();

        let mut card_param = Vec::new();
        for (j, card) in cards.iter().enumerate() {
            let data = hex::decode(card.strip_prefix("0x").unwrap_or(&card))
                .expect(&format!("hex decode {} {} output error", i, j));
            card_param.push(data)
        }
        let output =
            bytes_2_masked_card(&card_param).expect(&format!("hex decode {} output error", i));
        output_param.push(output)
    }

    let proof: ShuffleProof = {
        let data = hex::decode(proof.strip_prefix("0x").unwrap_or(&proof))
            .expect("hex decode proof error");
        ShuffleProof::from_bytes_be::<TurboCS>(&data).expect("ShuffleProof from_bytes_be error")
    };

    verify_shuffle(&verifier_params, &input_param, &output_param, &proof).is_ok()
}
