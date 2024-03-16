mod card_maps;
mod utils;

mod poker;
pub use poker::*;

use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::{BigInteger, One, PrimeField};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Mutex};
use wasm_bindgen::prelude::*;
use uzkge::{
    chaum_pedersen::dl::ChaumPedersenDLProof,
    gen_params::{ProverParams, VerifierParams},
};
use zshuffle::{
    build_cs::{prove_shuffle, verify_shuffle},
    gen_params::{gen_shuffle_prover_params, params::refresh_prover_params_public_key},
    keygen::{aggregate_keys as core_aggregate_keys, Keypair as CoreKeypair},
    mask::*,
    reveal::*,
    MaskedCard as Masked,
};

use card_maps::CARD_MAPS;
use utils::{
    default_prng, error_to_jsvalue, hex_to_point, hex_to_scalar, point_to_hex, point_to_uncompress,
    scalar_to_hex, shuffle_proof_from_hex, shuffle_proof_to_hex, uncompress_to_point,
};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

static PARAMS: Lazy<Mutex<HashMap<usize, ProverParams>>> = Lazy::new(|| {
    let m = HashMap::new();
    Mutex::new(m)
});

#[derive(Serialize, Deserialize)]
pub struct Keypair {
    /// 0xHex (U256)
    pub sk: String,
    /// 0xHex (U256)
    pub pk: String,
    /// public key uncompress x, y
    pub pkxy: (String, String),
}

/// e2.0, e2.1, e1.0, e1.1
#[derive(Serialize, Deserialize, Clone)]
pub struct MaskedCard(pub String, pub String, pub String, pub String);

#[derive(Serialize, Deserialize)]
pub struct MaskedCardWithProof {
    /// MaskedCard
    pub card: MaskedCard,
    /// hex string
    pub proof: String,
}

#[derive(Serialize, Deserialize)]
pub struct RevealedCardWithProof {
    /// MaskedCard
    pub card: (String, String),
    /// hex string
    pub proof: String,
}

#[derive(Serialize, Deserialize)]
pub struct ShuffledCardsWithProof {
    /// MaskedCard
    pub cards: Vec<MaskedCard>,
    /// hex string
    pub proof: String,
}

/// uncompress public key to x, y
#[wasm_bindgen]
pub fn public_uncompress(pk_s: String) -> Result<JsValue, JsValue> {
    let pk = hex_to_point::<EdwardsProjective>(&pk_s)?;
    let pkxy = point_to_uncompress(&pk, true);
    Ok(serde_wasm_bindgen::to_value(&pkxy)?)
}

/// comporess (public_x, public_y) to public
#[wasm_bindgen]
pub fn public_compress(publics: JsValue) -> Result<String, JsValue> {
    let publicxy: (String, String) = serde_wasm_bindgen::from_value(publics)?;
    let pk = uncompress_to_point(&publicxy.0, &publicxy.1)?;
    Ok(point_to_hex(&pk, true))
}

/// generate keypair
#[wasm_bindgen]
pub fn generate_key() -> Result<JsValue, JsValue> {
    let mut prng = default_prng();
    let keypair = CoreKeypair::generate(&mut prng);
    let pkxy = point_to_uncompress(&keypair.public, true);

    let ret = Keypair {
        sk: scalar_to_hex(&keypair.secret, true),
        pk: point_to_hex(&keypair.public, true),
        pkxy,
    };

    Ok(serde_wasm_bindgen::to_value(&ret)?)
}

/// aggregate all pk to joint pk
#[wasm_bindgen]
pub fn aggregate_keys(publics: JsValue) -> Result<String, JsValue> {
    let publics: Vec<String> = serde_wasm_bindgen::from_value(publics)?;
    let mut pks = vec![];
    for bytes in publics {
        pks.push(hex_to_point(&bytes)?);
    }
    let pk = core_aggregate_keys(&pks).map_err(error_to_jsvalue)?;
    Ok(point_to_hex(&pk, true))
}

/// mask the card, return the masked card and masked proof
#[wasm_bindgen]
pub fn init_masked_cards(joint: String, num: i32) -> Result<JsValue, JsValue> {
    if CARD_MAPS.len() < num as usize {
        return Err(error_to_jsvalue("The number of cards exceeds the maximum"));
    }

    let mut prng = default_prng();
    let joint_pk = hex_to_point(&joint)?;

    let mut deck = vec![];
    for n in 0..num {
        let point = index_to_point(n);

        let (masked_card, masked_proof) =
            mask(&mut prng, &joint_pk, &point, &Fr::one()).map_err(error_to_jsvalue)?;

        deck.push(MaskedCardWithProof {
            card: masked_card_serialize(&masked_card),
            proof: format!(
                "0x{}",
                hex::encode(&bincode::serialize(&masked_proof).map_err(error_to_jsvalue)?)
            ),
        });
    }

    Ok(serde_wasm_bindgen::to_value(&deck)?)
}

/// mask the card, return the masked card and masked proof
#[wasm_bindgen]
pub fn mask_card(joint: String, index: i32) -> Result<JsValue, JsValue> {
    let mut prng = default_prng();
    let joint_pk = hex_to_point(&joint)?;
    let point = index_to_point(index);
    let (masked_card, masked_proof) =
        mask(&mut prng, &joint_pk, &point, &Fr::one()).map_err(error_to_jsvalue)?;

    let ret = MaskedCardWithProof {
        card: masked_card_serialize(&masked_card),
        proof: format!(
            "0x{}",
            hex::encode(&bincode::serialize(&masked_proof).map_err(error_to_jsvalue)?)
        ),
    };

    Ok(serde_wasm_bindgen::to_value(&ret)?)
}

/// verify masked card with the proof
#[wasm_bindgen]
pub fn verify_masked_card(
    joint: String,
    index: i32,
    masked: JsValue,
    proof: String,
) -> Result<bool, JsValue> {
    let masked: MaskedCard = serde_wasm_bindgen::from_value(masked)?;

    let joint_pk = hex_to_point(&joint)?;
    let point = index_to_point(index);
    let masked = masked_card_deserialize(&masked)?;

    let hex = proof.trim_start_matches("0x");
    let masked_proof = bincode::deserialize(&hex::decode(hex).map_err(error_to_jsvalue)?)
        .map_err(error_to_jsvalue)?;

    Ok(verify_mask(&joint_pk, &point, &masked, &masked_proof).is_ok())
}

/// Initialize the prover key
#[wasm_bindgen]
pub fn init_prover_key(num: i32) {
    let n = num as usize;

    let mut params = PARAMS.lock().unwrap();
    if params.get(&n).is_none() {
        let pp = gen_shuffle_prover_params(n)
            .map_err(error_to_jsvalue)
            .unwrap();
        params.insert(n, pp);
    }
    drop(params);
}

/// refresh joint public key when it changed.
#[wasm_bindgen]
pub fn refresh_joint_key(joint: String, num: i32) -> Result<Vec<String>, JsValue> {
    let joint_pk = hex_to_point(&joint)?;
    let n = num as usize;

    let mut params = PARAMS.lock().unwrap();
    let prover_params = if let Some(param) = params.get_mut(&n) {
        param
    } else {
        let pp = gen_shuffle_prover_params(n)
            .map_err(error_to_jsvalue)
            .unwrap();
        params.insert(n, pp);
        params.get_mut(&n).unwrap()
    };

    let pkc =
        refresh_prover_params_public_key(prover_params, &joint_pk).map_err(error_to_jsvalue)?;
    drop(params);

    let mut pkc_string: Vec<_> = vec![];
    for p in pkc {
        let (x, y) = point_to_uncompress(&p, true);
        pkc_string.push(x);
        pkc_string.push(y);
    }

    Ok(pkc_string)
}

/// shuffle the cards and shuffled proof
#[wasm_bindgen]
pub fn shuffle_cards(joint: String, deck: JsValue) -> Result<JsValue, JsValue> {
    let deck: Vec<MaskedCard> = serde_wasm_bindgen::from_value(deck)?;
    let n = deck.len();

    let mut prng = default_prng();
    let joint_pk = hex_to_point(&joint)?;

    let mut masked_deck = vec![];
    for card in deck {
        masked_deck.push(masked_card_deserialize(&card)?);
    }

    let params = PARAMS.lock().unwrap();
    let prover_params = params
        .get(&n)
        .expect("Missing PARAMS, need init & refresh pk");

    let (shuffled_proof, new_deck) =
        prove_shuffle(&mut prng, &joint_pk, &masked_deck, &prover_params)
            .map_err(error_to_jsvalue)?;
    drop(params);

    let masked_cards: Vec<_> = new_deck
        .iter()
        .map(|card| masked_card_serialize(&card))
        .collect();

    let ret = ShuffledCardsWithProof {
        cards: masked_cards,
        proof: shuffle_proof_to_hex(&shuffled_proof),
    };

    Ok(serde_wasm_bindgen::to_value(&ret)?)
}

/// verify the shuffled cards
#[wasm_bindgen]
pub fn verify_shuffled_cards(
    deck1: JsValue,
    deck2: JsValue,
    proof: String,
) -> Result<bool, JsValue> {
    let deck1: Vec<MaskedCard> = serde_wasm_bindgen::from_value(deck1)?;
    let deck2: Vec<MaskedCard> = serde_wasm_bindgen::from_value(deck2)?;

    let n = deck1.len();
    let mut masked_deck1 = vec![];
    for card in deck1 {
        masked_deck1.push(masked_card_deserialize(&card)?);
    }
    let mut masked_deck2 = vec![];
    for card in deck2 {
        masked_deck2.push(masked_card_deserialize(&card)?);
    }
    let shuffled_proof = shuffle_proof_from_hex(&proof)?;

    let params = PARAMS.lock().unwrap();
    let prover_params = params
        .get(&n)
        .expect("Missing PARAMS, need init & refresh pk");
    let verifier_params = VerifierParams::from(prover_params);

    Ok(verify_shuffle(
        &verifier_params,
        &masked_deck1,
        &masked_deck2,
        &shuffled_proof,
    )
    .is_ok())
}

/// compute masked to revealed card and the revealed proof
#[wasm_bindgen]
pub fn reveal_card(sk: String, card: JsValue) -> Result<JsValue, JsValue> {
    let card: MaskedCard = serde_wasm_bindgen::from_value(card)?;

    let mut prng = default_prng();
    let keypair = CoreKeypair::from_secret(hex_to_scalar(&sk)?);
    let masked = masked_card_deserialize(&card)?;

    let (reveal_card, reveal_proof) =
        reveal(&mut prng, &keypair, &masked).map_err(error_to_jsvalue)?;

    let ret = RevealedCardWithProof {
        card: point_to_uncompress(&reveal_card, true),
        proof: format!("0x{}", hex::encode(&reveal_proof.to_uncompress())),
    };

    Ok(serde_wasm_bindgen::to_value(&ret)?)
}

/// verify reveal point
#[wasm_bindgen]
pub fn verify_revealed_card(pk: String, card: JsValue, reveal: JsValue) -> Result<bool, JsValue> {
    let card: MaskedCard = serde_wasm_bindgen::from_value(card)?;
    let reveal: RevealedCardWithProof = serde_wasm_bindgen::from_value(reveal)?;

    let pk = hex_to_point(&pk)?;
    let masked = masked_card_deserialize(&card)?;

    let reveal_card = uncompress_to_point(&reveal.card.0, &reveal.card.1)?;
    let hex = reveal.proof.trim_start_matches("0x");
    let reveal_proof =
        ChaumPedersenDLProof::from_uncompress(&hex::decode(hex).map_err(error_to_jsvalue)?)
            .map_err(error_to_jsvalue)?;

    Ok(verify_reveal(&pk, &masked, &reveal_card, &reveal_proof).is_ok())
}

/// unmask the card use others' reveals
#[wasm_bindgen]
pub fn unmask_card(sk: String, card: JsValue, reveals: JsValue) -> Result<i32, JsValue> {
    let card: MaskedCard = serde_wasm_bindgen::from_value(card)?;
    let reveals: Vec<(String, String)> = serde_wasm_bindgen::from_value(reveals)?;

    let mut prng = default_prng();
    let keypair = CoreKeypair::from_secret(hex_to_scalar(&sk)?);
    let masked = masked_card_deserialize(&card)?;

    let mut reveal_cards = vec![];
    for reveal in reveals {
        reveal_cards.push(uncompress_to_point(&reveal.0, &reveal.1)?);
    }

    let (reveal_card, _proof) = reveal(&mut prng, &keypair, &masked).map_err(error_to_jsvalue)?;
    reveal_cards.push(reveal_card);

    let unmasked_card = unmask(&masked, &reveal_cards).map_err(error_to_jsvalue)?;
    point_to_index(unmasked_card)
}

/// decode masked to card use all reveals
#[wasm_bindgen]
pub fn decode_point(card: JsValue, reveals: JsValue) -> Result<i32, JsValue> {
    let card: MaskedCard = serde_wasm_bindgen::from_value(card)?;
    let reveals: Vec<(String, String)> = serde_wasm_bindgen::from_value(reveals)?;

    let masked = masked_card_deserialize(&card)?;
    let mut reveal_cards = vec![];
    for reveal in reveals {
        reveal_cards.push(uncompress_to_point(&reveal.0, &reveal.1)?);
    }

    let unmasked_card = unmask(&masked, &reveal_cards).map_err(error_to_jsvalue)?;
    point_to_index(unmasked_card)
}

fn index_to_point(index: i32) -> EdwardsProjective {
    let y_hex = CARD_MAPS[index as usize].trim_start_matches("0x");
    let y_bytes = hex::decode(y_hex).unwrap();
    let y = Fq::from_be_bytes_mod_order(&y_bytes);

    let affine = EdwardsAffine::get_point_from_y_unchecked(y, true).unwrap();
    affine.into()
}

fn point_to_index(point: EdwardsProjective) -> Result<i32, JsValue> {
    let affine = EdwardsAffine::from(point);
    let y_bytes = affine.y.into_bigint().to_bytes_be();
    let bytes = format!("0x{}", hex::encode(&y_bytes));

    if let Some(pos) = CARD_MAPS.iter().position(|y| y == &bytes) {
        Ok(pos as i32)
    } else {
        Err(error_to_jsvalue("Point not map to  a card"))
    }
}

fn masked_card_serialize(masked: &Masked) -> MaskedCard {
    let (e1_x, e1_y) = point_to_uncompress(&masked.e1, true);
    let (e2_x, e2_y) = point_to_uncompress(&masked.e2, true);
    MaskedCard(e2_x, e2_y, e1_x, e1_y)
}

fn masked_card_deserialize(masked: &MaskedCard) -> Result<Masked, JsValue> {
    let e2 = uncompress_to_point(&masked.0, &masked.1)?;
    let e1 = uncompress_to_point(&masked.2, &masked.3)?;
    Ok(Masked { e1, e2 })
}
