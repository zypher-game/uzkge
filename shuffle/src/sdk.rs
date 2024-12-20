use std::collections::HashMap;
use uzkge::{
    gen_params::{ProverParams, VerifierParams},
};
use std::sync::Mutex;
use once_cell::sync::Lazy;
use crate::gen_params::{gen_shuffle_prover_params,params::refresh_prover_params_public_key};
use crate::error::{ShuffleResult,ShuffleError};
use crate::utils::{default_prng,point_to_hex,
    point_to_uncompress,hex_to_point,hex_to_scalar,
    shuffle_proof_to_hex,shuffle_proof_from_hex,scalar_to_hex,uncompress_to_point,};
use crate::card_maps::CARD_MAPS;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::{BigInteger, One, PrimeField};
use crate::{
    mask::mask,
    build_cs::{prove_shuffle, verify_shuffle},
    keygen::{aggregate_keys as core_aggregate_keys, Keypair as CoreKeypair},
    reveal::*,
    reveal_with_snark::RevealCircuit,
    Groth16,ProvingKey,gen_params::load_groth16_pk,SNARK,
    MaskedCard as Masked
};
use ark_ec::AffineRepr;
use serde::{Serialize,Deserialize};


static PARAMS: Lazy<Mutex<HashMap<usize, ProverParams>>> = Lazy::new(|| {
    let m = HashMap::new();
    Mutex::new(m)
});

const GROTH16_N: usize = 52;

static GROTH16_PARAMS: Lazy<Mutex<HashMap<usize, ProvingKey<ark_bn254::Bn254>>>> =
    Lazy::new(|| {
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
pub struct RevealedCardWithSnarkProof {
    pub card: (String, String),
    pub snark_proof: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ShuffledCardsWithProof {
    /// MaskedCard
    pub cards: Vec<MaskedCard>,
    /// hex string
    pub proof: String,
}
    

fn index_to_point(index: i32) -> EdwardsProjective {
    let y_hex = CARD_MAPS[index as usize].trim_start_matches("0x");
    let y_bytes = hex::decode(y_hex).unwrap();
    let y = Fq::from_be_bytes_mod_order(&y_bytes);

    let affine = EdwardsAffine::get_point_from_y_unchecked(y, true).unwrap();
    affine.into()
}

fn point_to_index(point: EdwardsProjective) -> ShuffleResult<i32> {
    let affine = EdwardsAffine::from(point);
    let y_bytes = affine.y.into_bigint().to_bytes_be();
    let bytes = format!("0x{}", hex::encode(&y_bytes));

    if let Some(pos) = CARD_MAPS.iter().position(|y| y == &bytes) {
        Ok(pos as i32)
    } else {
        Err(ShuffleError::RangeError("Point not map to a card".to_owned()))
    }
}

fn masked_card_serialize(masked: &Masked) -> MaskedCard {
    let (e1_x, e1_y) = point_to_uncompress(&masked.e1, true);
    let (e2_x, e2_y) = point_to_uncompress(&masked.e2, true);
    MaskedCard(e2_x, e2_y, e1_x, e1_y)
}

fn masked_card_deserialize(masked: &MaskedCard) -> ShuffleResult<Masked> {
    let e2 = uncompress_to_point(&masked.0, &masked.1)?;
    let e1 = uncompress_to_point(&masked.2, &masked.3)?;
    Ok(Masked { e1, e2 })
}


pub fn init_prover_key(num: i32)->ShuffleResult<()> {
    let n = num as usize;

    let mut params = PARAMS.lock().unwrap();
    if params.get(&n).is_none() {
        let pp = gen_shuffle_prover_params(n).map_err(|e| ShuffleError::UzkgeError(e))?;
        params.insert(n, pp);
    }
    drop(params);
    Ok(())
}

pub fn aggregate_keys(publics:  Vec<String>) -> ShuffleResult<String> {
    let mut pks = vec![];
    for bytes in publics {
        pks.push(hex_to_point(&bytes)?);
    }
    let pk = core_aggregate_keys(&pks).map_err(|e| ShuffleError::UzkgeError(e))?;
    Ok(point_to_hex(&pk, true))
}


pub fn refresh_joint_key(joint: String, num: i32) -> ShuffleResult<Vec<String>> {
    let joint_pk = hex_to_point(&joint)?;
    let n = num as usize;

    let mut params = PARAMS.lock().unwrap();
    let prover_params = if let Some(param) = params.get_mut(&n) {
        param
    } else {
        let pp = gen_shuffle_prover_params(n)
            .unwrap();
        params.insert(n, pp);
        params.get_mut(&n).unwrap()
    };
    let pkc =
        refresh_prover_params_public_key(prover_params, &joint_pk).map_err(|e| ShuffleError::UzkgeError(e))?;
    drop(params);

    let mut pkc_string: Vec<_> = vec![];
    for p in pkc {
        let (x, y) = point_to_uncompress(&p, true);
        pkc_string.push(x);
        pkc_string.push(y);
    }
    Ok(pkc_string)
}

pub fn init_masked_cards(joint: String, num: i32) -> ShuffleResult<Vec<MaskedCardWithProof>> {
    if CARD_MAPS.len() < num as usize {
        return Err(ShuffleError::RangeError("The number of cards exceeds the maximum".to_owned()));
    }

    let mut prng = default_prng();
    let joint_pk = hex_to_point(&joint)?;

    let mut deck = vec![];
    for n in 0..num {
        let point = index_to_point(n);

        let (masked_card, masked_proof) =
            mask(&mut prng, &joint_pk, &point, &Fr::one()).map_err(|e| ShuffleError::UzkgeError(e))?;

        deck.push(MaskedCardWithProof {
            card: masked_card_serialize(&masked_card),
            proof: format!(
                "0x{}",
                hex::encode(&bincode::serialize(&masked_proof)?)
            ),
        });
    }

    Ok(deck)
}

pub fn shuffle_cards(joint: String, deck: Vec<MaskedCard>) -> ShuffleResult<ShuffledCardsWithProof> {
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
        prove_shuffle(&mut prng, &joint_pk, &masked_deck, &prover_params).map_err(|e| ShuffleError::UzkgeError(e))?;
    drop(params);

    let masked_cards: Vec<_> = new_deck
        .iter()
        .map(|card| masked_card_serialize(&card))
        .collect();

    let ret = ShuffledCardsWithProof {
        cards: masked_cards,
        proof: shuffle_proof_to_hex(&shuffled_proof),
    };

    Ok(ret)
}

pub fn verify_shuffled_cards(
    deck1: Vec<MaskedCard>,
    deck2: Vec<MaskedCard>,
    proof: String,
) -> ShuffleResult<bool> {

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

pub fn init_reveal_key() {
    let mut params = GROTH16_PARAMS.lock().unwrap();
    if params.get(&GROTH16_N).is_none() {
        let pp = load_groth16_pk(GROTH16_N).unwrap();
        params.insert(GROTH16_N, pp);
    }
    drop(params);
}

pub fn reveal_card(sk: String, card: MaskedCard) -> ShuffleResult<RevealedCardWithProof> {

    let mut prng = default_prng();
    let keypair = CoreKeypair::from_secret(hex_to_scalar(&sk)?);
    let masked = masked_card_deserialize(&card)?;

    let (reveal_card, reveal_proof) =
        reveal(&mut prng, &keypair, &masked).map_err(|e| ShuffleError::UzkgeError(e))?;

    let ret = RevealedCardWithProof {
        card: point_to_uncompress(&reveal_card, true),
        proof: format!("0x{}", hex::encode(&reveal_proof.to_uncompress())),
    };

    Ok(ret)
}

/// compute masked to revealed card with a snark proof
pub fn reveal_card_with_snark(sk: String, card: MaskedCard) -> ShuffleResult<RevealedCardWithSnarkProof> {
    let mut prng = default_prng();
    let keypair = CoreKeypair::from_secret(hex_to_scalar(&sk)?);
    let masked = masked_card_deserialize(&card)?;
    {
        init_reveal_key();
    }
    let reveal_card = masked.e1 * keypair.secret;
    
    let params = GROTH16_PARAMS.lock().unwrap();
    let prover_params = params
        .get(&GROTH16_N)
        .expect("Missing PARAMS, need init & refresh pk");

    let circuit = RevealCircuit::new(&keypair.secret, &masked, &reveal_card);
    let proof = Groth16::<ark_bn254::Bn254>::prove(&prover_params, circuit, &mut prng).unwrap();
    drop(params);

    let a = proof.a.xy().unwrap();
    let b = proof.b.xy().unwrap();
    let c = proof.c.xy().unwrap();

    let snark_proof = vec![
        scalar_to_hex(&a.0, true),
        scalar_to_hex(&a.1, true),
        scalar_to_hex(&b.0.c1, true),
        scalar_to_hex(&b.0.c0, true),
        scalar_to_hex(&b.1.c1, true),
        scalar_to_hex(&b.1.c0, true),
        scalar_to_hex(&c.0, true),
        scalar_to_hex(&c.1, true),
    ];

    let ret = RevealedCardWithSnarkProof {
        card: point_to_uncompress(&reveal_card, true),
        snark_proof,
    };

    Ok(ret)
}

pub fn unmask_card(sk: String, card: MaskedCard, reveals:  Vec<(String, String)>) -> ShuffleResult<i32> {
    
    let mut prng = default_prng();
    let keypair = CoreKeypair::from_secret(hex_to_scalar(&sk)?);
    let masked = masked_card_deserialize(&card)?;

    let mut reveal_cards = vec![];
    for reveal in reveals {
        reveal_cards.push(uncompress_to_point(&reveal.0, &reveal.1)?);
    }

    let (reveal_card, _proof) = reveal(&mut prng, &keypair, &masked).map_err(|e| ShuffleError::UzkgeError(e))?;
    reveal_cards.push(reveal_card);

    let unmasked_card = unmask(&masked, &reveal_cards).map_err(|e| ShuffleError::UzkgeError(e))?;
    point_to_index(unmasked_card)
}


#[cfg(test)]
pub mod tests{
    use crate::utils::tests::generate_key_preset;
    use super::*;
    const CARD_NUM: i32 = 20;

    #[test]
    fn mask_and_shuffle(){

        init_prover_key(CARD_NUM).unwrap();

        let key1 = generate_key_preset("0x020b31a672b203b71241031c8ea5e5a4ef133c57bcde822ac514e8a1c7f89124".to_owned(),
        "0xada2d401ec3113060a049b5472550965f59423eaaeec3133dd33628e5df50491".to_owned(),
        "0x27f9bc87a7fe674c14532699864907156753a8271a6e97b8f8b99a474ad2afdd".to_owned(),
        "0x1104f55d8e6233dd3331ecaeea2394f565095572549b040a061331ec01d4a2ad".to_owned(),
        ).unwrap();
        let key2 = generate_key_preset("0x02d75fed474808cbacf1ff1e2455a30779839cfb32cd79e2020aa603094b80b7".to_owned(),
        "0x52bd82819071b9b913aacfccc6657e5226d1aebd5e5ec4fbdea0b6f5bb2bdf12".to_owned(),
        "0x0fc2c87764783cdc883744c16712654ce3d0fccbea70c9ce379a8bc7f412f006".to_owned(),
        "0x12df2bbbf5b6a0defbc45e5ebdaed126527e65c6cccfaa13b9b971908182bd52".to_owned(),
        ).unwrap();
        
        let joint = vec![key1.pk, key2.pk]; // key3.pk, key4.pk
         
        let joint_pk = aggregate_keys(joint).unwrap();
        
        assert_eq!(joint_pk,"0x9723835eb88d3c9e76f6d0c1295724e4f76fd0762568dee9a79394760510659d");

        let _pkc = refresh_joint_key(joint_pk.clone(), CARD_NUM).unwrap();
        
        let decks = init_masked_cards(joint_pk.clone(), CARD_NUM).unwrap();

        let deck_cards: Vec<MaskedCard> = decks.iter().map(|v| v.card.clone()).collect();

        let proof: ShuffledCardsWithProof = shuffle_cards(joint_pk.clone(), deck_cards.clone()).unwrap();

        let cards = proof.cards.clone();
        let res =
            verify_shuffled_cards(deck_cards.clone(), cards.clone(), proof.proof.clone()).unwrap();
        assert_eq!(res, true);
 
        init_reveal_key();
        
        let reveal_item=cards[0].clone();
        let key2_reveal_proof = reveal_card_with_snark(key2.sk.clone(),reveal_item.clone()).unwrap();
        
        let unmasked_card = unmask_card(key1.sk.clone(), reveal_item.clone(),vec![key2_reveal_proof.card]).unwrap();
        println!("unmasked_card={:?}",unmasked_card);
        

    }
}