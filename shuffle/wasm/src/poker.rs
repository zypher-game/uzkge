use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::utils::error_to_jsvalue;

/// suite from 1..4
/// value from 1..13
/// if suite is 0, it will be joker, value is 53, 54
#[derive(Serialize, Deserialize)]
pub struct PokerCard {
    pub suite: i32,
    pub value: i32,
}

#[wasm_bindgen]
pub fn card_to_index(value: JsValue) -> Result<i32, JsValue> {
    let card: PokerCard = serde_wasm_bindgen::from_value(value)?;
    if card.value > 52 {
        Ok(card.value - 1)
    } else {
        Ok((card.suite - 1) * 13 + (card.value - 1))
    }
}

#[wasm_bindgen]
pub fn index_to_card(index: i32) -> Result<JsValue, JsValue> {
    if index > 52 {
        return Err(error_to_jsvalue("Index not map to a card"));
    }

    let card = if index == 52 {
        PokerCard {
            suite: 0,
            value: 53,
        }
    } else if index == 53 {
        PokerCard {
            suite: 0,
            value: 53,
        }
    } else {
        let suite = index / 13 + 1;
        let value = index % 13 + 1;
        PokerCard { suite, value }
    };

    Ok(serde_wasm_bindgen::to_value(&card)?)
}
