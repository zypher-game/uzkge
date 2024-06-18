//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;
use web_sys::console::log_1;
use zshuffle_wasm::*;

const CARD_NUM: i32 = 20;

#[wasm_bindgen_test]
fn pass() {
    init_prover_key(CARD_NUM);

    let key1 = generate_key().unwrap();
    let key2 = generate_key().unwrap();
    let key3 = generate_key().unwrap();
    let key4 = generate_key().unwrap();
    let key1: Keypair = serde_wasm_bindgen::from_value(key1).unwrap();
    let key2: Keypair = serde_wasm_bindgen::from_value(key2).unwrap();
    let key3: Keypair = serde_wasm_bindgen::from_value(key3).unwrap();
    let key4: Keypair = serde_wasm_bindgen::from_value(key4).unwrap();

    let joint = [key1.public, key2.public, key3.public, key4.public];
    let joint_values = serde_wasm_bindgen::to_value(&joint).unwrap();
    let joint_pk = aggregate_keys(joint_values).unwrap();

    // must do it before prov & verify.
    // when joint pk changed, must do it again !!!
    let pkc = refresh_joint_key(joint_pk.clone(), CARD_NUM).unwrap();

    let init_deck = init_masked_cards(joint_pk.clone(), CARD_NUM).unwrap();
    let decks: Vec<MaskedCardWithProof> = serde_wasm_bindgen::from_value(init_deck).unwrap();
    let deck_cards: Vec<MaskedCard> = decks.iter().map(|v| v.card.clone()).collect();
    let first_deck = serde_wasm_bindgen::to_value(&deck_cards).unwrap();

    let proof = shuffle_cards(joint_pk.clone(), first_deck.clone()).unwrap();
    let proof: ShuffledCardsWithProof = serde_wasm_bindgen::from_value(proof).unwrap();
    let cards = serde_wasm_bindgen::to_value(&proof.cards).unwrap();
    let res =
        verify_shuffled_cards(first_deck.clone(), cards.clone(), proof.proof.clone()).unwrap();
    assert_eq!(res, true);

    log_1(&"PROOF:".into());
    log_1(&proof.proof.into());
    log_1(&"DECK1:".into());
    let deck1_v: Vec<MaskedCard> = serde_wasm_bindgen::from_value(first_deck).unwrap();
    for d in deck1_v {
        log_1(&format!("\"{}\",", d.0).into());
        log_1(&format!("\"{}\",", d.1).into());
        log_1(&format!("\"{}\",", d.2).into());
        log_1(&format!("\"{}\",", d.3).into());
    }
    log_1(&"DECK2:".into());
    let deck2_v: Vec<MaskedCard> = serde_wasm_bindgen::from_value(cards).unwrap();
    for d in deck2_v {
        log_1(&format!("\"{}\",", d.0).into());
        log_1(&format!("\"{}\",", d.1).into());
        log_1(&format!("\"{}\",", d.2).into());
        log_1(&format!("\"{}\",", d.3).into());
    }
    log_1(&"PKC:".into());
    for p in pkc {
        log_1(&format!("\"{}\",", p).into());
    }
}
