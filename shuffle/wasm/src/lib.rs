mod card_maps;
mod utils;

use ark_bn254::G1Projective;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::{BigInteger, One, PrimeField};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zplonk::{chaum_pedersen::dl::ChaumPedersenDLProof, gen_params::VerifierParams};
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
    default_prng, error_to_jsvalue, export_proof, hex_to_point, hex_to_scalar, point_to_hex,
    point_to_uncompress, scalar_to_hex, uncompress_to_point,
};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[derive(Serialize, Deserialize)]
pub struct Keypair {
    /// 0xHex (U256)
    pub secret: String,
    /// 0xHex (U256)
    pub public: String,
    /// public uncompress x, y
    pub publicxy: (String, String),
}

/// e2.0, e2.1, e1.0, e1.1
#[derive(Serialize, Deserialize, Clone)]
pub struct MaskedCard(pub String, pub String, pub String, pub String);

/// suite from 1..4
/// value from 1..13
/// if suite is 0, it will be joker, value is 53, 54
#[derive(Serialize, Deserialize)]
pub struct Card {
    pub suite: i32,
    pub value: i32,
}

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
    /// pk commitment for contract verify
    pub pkc: Vec<String>,
    /// hex string
    pub proof: String,
}

/// uncompress public key to x, y
#[wasm_bindgen]
pub fn public_uncompress(public: String) -> Result<JsValue, JsValue> {
    let pk = hex_to_point(&public)?;
    let publicxy = point_to_uncompress(&pk);
    Ok(serde_wasm_bindgen::to_value(&publicxy)?)
}

/// comporess (public_x, public_y) to public
#[wasm_bindgen]
pub fn public_compress(publics: JsValue) -> Result<String, JsValue> {
    let publicxy: (String, String) = serde_wasm_bindgen::from_value(publics)?;
    let pk = uncompress_to_point(&publicxy.0, &publicxy.1)?;
    Ok(point_to_hex(&pk))
}

/// generate keypair
#[wasm_bindgen]
pub fn generate_key() -> Result<JsValue, JsValue> {
    let mut prng = default_prng();
    let keypair = CoreKeypair::generate(&mut prng);
    let publicxy = point_to_uncompress(&keypair.public);

    let ret = Keypair {
        secret: scalar_to_hex(&keypair.secret),
        public: point_to_hex(&keypair.public),
        publicxy,
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
    Ok(point_to_hex(&pk))
}

/// mask the card, return the masked card and masked proof
#[wasm_bindgen]
pub fn init_masked_cards(joint: String, has_joker: bool) -> Result<JsValue, JsValue> {
    let mut prng = default_prng();
    let joint_pk = hex_to_point(&joint)?;
    let mut deck = vec![];

    for suite in 1..5 {
        for value in 1..14 {
            let point = card_to_point(Card { suite, value });

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
    }

    if has_joker {
        for value in [53, 54] {
            let point = card_to_point(Card { suite: 0, value });
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
    }

    Ok(serde_wasm_bindgen::to_value(&deck)?)
}

/// mask the card, return the masked card and masked proof
#[wasm_bindgen]
pub fn mask_card(joint: String, card: JsValue) -> Result<JsValue, JsValue> {
    let card: Card = serde_wasm_bindgen::from_value(card)?;

    let mut prng = default_prng();
    let joint_pk = hex_to_point(&joint)?;
    let point = card_to_point(card);
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
    card: JsValue,
    masked: JsValue,
    proof: String,
) -> Result<bool, JsValue> {
    let card: Card = serde_wasm_bindgen::from_value(card)?;
    let masked: MaskedCard = serde_wasm_bindgen::from_value(masked)?;

    let joint_pk = hex_to_point(&joint)?;
    let point = card_to_point(card);
    let masked = masked_card_deserialize(&masked)?;

    let hex = proof.trim_start_matches("0x");
    let masked_proof = bincode::deserialize(&hex::decode(hex).map_err(error_to_jsvalue)?)
        .map_err(error_to_jsvalue)?;

    Ok(verify_mask(&joint_pk, &point, &masked, &masked_proof).is_ok())
}

/// Initialize the prover key
#[wasm_bindgen]
pub fn init_prover_key() -> Result<(), JsValue> {
    //drop(PROVER_PARAMS.lock().map_err(error_to_jsvalue)?); TODO
    Ok(())
}

// /// Refresh the public key
// #[wasm_bindgen]
// pub fn refresh_public_key(joint_pk: String) -> Result<Vec<String>, JsValue> {
//     let joint_pk = hex_to_point(&joint_pk)?;
//     // let mut pp = PROVER_PARAMS.lock().map_err(error_to_jsvalue)?;
//     // pp.refresh_public_key(&joint_pk).map_err(error_to_jsvalue)?;

//     let mut cm_pk = vec![];

//     for cm in pp
//         .prover_params
//         .verifier_params
//         .cm_shuffle_public_key_vec
//         .iter()
//     {
//         let tmp: G1Affine = cm.0.into();
//         let (x, y) = tmp.xy().unwrap();
//         let x: BigUint = x.into();
//         cm_pk.push(x.to_str_radix(16));
//         let y: BigUint = y.into();
//         cm_pk.push(y.to_str_radix(16));
//     }

//     Ok(cm_pk)
// }

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

    let mut prover_params = gen_shuffle_prover_params(n).map_err(error_to_jsvalue)?;
    let pkc = refresh_prover_params_public_key(&mut prover_params, &joint_pk)
        .map_err(error_to_jsvalue)?;

    let (shuffled_proof, new_deck) =
        prove_shuffle(&mut prng, &joint_pk, &masked_deck, &prover_params)
            .map_err(error_to_jsvalue)?;

    let masked_cards: Vec<_> = new_deck
        .iter()
        .map(|card| masked_card_serialize(&card))
        .collect();

    let mut pkc_string: Vec<_> = vec![];
    for p in pkc {
        let (x, y) = base_point_to_card(p);
        pkc_string.push(x);
        pkc_string.push(y);
    }

    let ret = ShuffledCardsWithProof {
        cards: masked_cards,
        pkc: pkc_string,
        proof: export_proof(&shuffled_proof),
    };

    Ok(serde_wasm_bindgen::to_value(&ret)?)
}

/// verify the shuffled cards
#[wasm_bindgen]
pub fn verify_shuffled_cards(
    joint: String,
    deck1: JsValue,
    deck2: JsValue,
    proof: String,
) -> Result<bool, JsValue> {
    let deck1: Vec<MaskedCard> = serde_wasm_bindgen::from_value(deck1)?;
    let deck2: Vec<MaskedCard> = serde_wasm_bindgen::from_value(deck2)?;
    return Ok(true); // TODO

    let n = deck1.len();
    let joint_pk = hex_to_point(&joint)?;
    let mut masked_deck1 = vec![];
    for card in deck1 {
        masked_deck1.push(masked_card_deserialize(&card)?);
    }
    let mut masked_deck2 = vec![];
    for card in deck2 {
        masked_deck2.push(masked_card_deserialize(&card)?);
    }

    let hex = proof.trim_start_matches("0x");
    let shuffled_proof = bincode::deserialize(&hex::decode(hex).map_err(error_to_jsvalue)?)
        .map_err(error_to_jsvalue)?;

    let mut prover_params = gen_shuffle_prover_params(n).map_err(error_to_jsvalue)?;
    refresh_prover_params_public_key(&mut prover_params, &joint_pk).map_err(error_to_jsvalue)?;
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
        card: point_to_uncompress(&reveal_card),
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
pub fn unmask_card(sk: String, card: JsValue, reveals: JsValue) -> Result<JsValue, JsValue> {
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
    let ret = point_to_card(unmasked_card)?;

    Ok(serde_wasm_bindgen::to_value(&ret)?)
}

/// decode masked to card use all reveals
#[wasm_bindgen]
pub fn decode_card(card: JsValue, reveals: JsValue) -> Result<JsValue, JsValue> {
    let card: MaskedCard = serde_wasm_bindgen::from_value(card)?;
    let reveals: Vec<(String, String)> = serde_wasm_bindgen::from_value(reveals)?;

    let masked = masked_card_deserialize(&card)?;
    let mut reveal_cards = vec![];
    for reveal in reveals {
        reveal_cards.push(uncompress_to_point(&reveal.0, &reveal.1)?);
    }

    let unmasked_card = unmask(&masked, &reveal_cards).map_err(error_to_jsvalue)?;
    let ret = point_to_card(unmasked_card)?;

    Ok(serde_wasm_bindgen::to_value(&ret)?)
}

fn card_to_point(card: Card) -> EdwardsProjective {
    let index = if card.value > 52 {
        card.value - 1
    } else {
        (card.suite - 1) * 13 + (card.value - 1)
    };

    let y_hex = CARD_MAPS[index as usize].trim_start_matches("0x");
    let y_bytes = hex::decode(y_hex).unwrap();
    let y = Fq::from_be_bytes_mod_order(&y_bytes);

    let affine = EdwardsAffine::get_point_from_y_unchecked(y, true).unwrap();
    affine.into()
}

fn masked_card_serialize(masked: &Masked) -> MaskedCard {
    let (e1_x, e1_y) = point_to_uncompress(&masked.e1);
    let (e2_x, e2_y) = point_to_uncompress(&masked.e2);
    MaskedCard(e2_x, e2_y, e1_x, e1_y)
}

fn masked_card_deserialize(masked: &MaskedCard) -> Result<Masked, JsValue> {
    let e2 = uncompress_to_point(&masked.0, &masked.1)?;
    let e1 = uncompress_to_point(&masked.2, &masked.3)?;
    Ok(Masked { e1, e2 })
}

fn point_to_card(point: EdwardsProjective) -> Result<Card, JsValue> {
    let affine = EdwardsAffine::from(point);
    let y_bytes = affine.y.into_bigint().to_bytes_be();
    let bytes = format!("0x{}", hex::encode(&y_bytes));

    if let Some(pos) = CARD_MAPS.iter().position(|y| y == &bytes) {
        if pos == 52 {
            Ok(Card {
                suite: 0,
                value: 53,
            })
        } else if pos == 53 {
            Ok(Card {
                suite: 0,
                value: 53,
            })
        } else {
            let suite = (pos / 13 + 1) as i32;
            let value = (pos % 13 + 1) as i32;
            Ok(Card { suite, value })
        }
    } else {
        Err(error_to_jsvalue("Point not map to  a card"))
    }
}

fn base_point_to_card(point: G1Projective) -> (String, String) {
    let affine = G1Projective::from(point);
    let x_bytes = affine.x.into_bigint().to_bytes_be();
    let y_bytes = affine.y.into_bigint().to_bytes_be();

    let x_s = format!("0x{}", hex::encode(&x_bytes));
    let y_s = format!("0x{}", hex::encode(&y_bytes));
    (x_s, y_s)
}
