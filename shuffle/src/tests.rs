use super::build_cs::{prove_shuffle, verify_shuffle};
use super::{keygen::*, mask::*, reveal::*, *};
use crate::parameters::{
    get_shuffle_verifier_params, refresh_prover_params_public_key, PROVER_PARAMS,
};
use ark_ed_on_bn254::{EdwardsAffine, Fr};
use ark_ff::{BigInteger, One, PrimeField, UniformRand};
use ark_std::rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use std::collections::HashMap;

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

#[derive(PartialEq, Clone, Eq, Copy)]
pub struct ClassicPlayingCard {
    value: Value,
    suite: Suite,
}

impl ClassicPlayingCard {
    pub fn new(value: Value, suite: Suite) -> Self {
        Self { value, suite }
    }
}

impl std::fmt::Debug for ClassicPlayingCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let suite = match self.suite {
            Suite::Club => "♣",
            Suite::Diamond => "♦",
            Suite::Heart => "♥",
            Suite::Spade => "♠",
        };

        let val = match self.value {
            Value::Two => "2",
            Value::Three => "3",
            Value::Four => "4",
            Value::Five => "5",
            Value::Six => "6",
            Value::Seven => "7",
            Value::Eight => "8",
            Value::Nine => "9",
            Value::Ten => "10",
            Value::Jack => "J",
            Value::Queen => "Q",
            Value::King => "K",
            Value::Ace => "A",
        };

        write!(f, "{}{}", suite, val)
    }
}

struct Player {
    keypair: Keypair,
    cards: Vec<MaskedCard>,
    opened_cards: Vec<Option<ClassicPlayingCard>>,
}

impl Player {
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R, _name: &str) -> Self {
        let keypair = Keypair::generate(rng);
        Self {
            keypair,
            cards: vec![],
            opened_cards: vec![],
        }
    }

    pub fn set_deck(&mut self, cards: &[MaskedCard]) {
        self.opened_cards = vec![None; cards.len()];
        self.cards = cards.to_vec();
    }

    pub fn unmask<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        mut reveal_cards: Vec<RevealCard>,
        card_mappings: &HashMap<Card, ClassicPlayingCard>,
        card: &MaskedCard,
    ) -> ClassicPlayingCard {
        let i = self.cards.iter().position(|x| x == card);
        let i = i.unwrap();

        let (own_reveal_card, _, _) = self.compute_reveal(rng, card);
        reveal_cards.push(own_reveal_card);

        let unmasked_card = unmask(card, &reveal_cards).unwrap();
        let opened_card = card_mappings.get(&unmasked_card).unwrap();

        self.opened_cards[i] = Some(*opened_card);

        *opened_card
    }

    pub fn compute_reveal<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        card: &MaskedCard,
    ) -> (RevealCard, RevealProof, PublicKey) {
        let (reveal_card, reveal_proof) = reveal(rng, &self.keypair, card).unwrap();

        (reveal_card, reveal_proof, self.keypair.public)
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
fn test_generate_cards_points() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    for _ in 0..54 {
        let p = EdwardsProjective::rand(&mut prng);
        let aa = EdwardsAffine::from(p);
        let bytes = aa.y.into_bigint().to_bytes_be();

        println!("\"0x{}\",", hex::encode(&bytes));
    }
}

#[test]
fn test_poker() {
    let mut rng = ChaChaRng::from_seed([0u8; 32]);

    let card_mapping = encode_cards(&mut rng);

    let mut alice = Player::new(&mut rng, "Alice");
    let mut bob = Player::new(&mut rng, "Bob");
    let mut charlie = Player::new(&mut rng, "Charlie");
    let mut david = Player::new(&mut rng, "David");

    let keys = vec![
        alice.keypair.public,
        bob.keypair.public,
        charlie.keypair.public,
        david.keypair.public,
    ];

    // Each player should run this computation. Alternatively, it can be ran by a smart contract
    let joint_pk = aggregate_keys(&keys).unwrap();

    // Each player should run this computation and verify that all players agree on the initial deck
    let mut deck = vec![];
    for card in card_mapping.keys() {
        let (masked_card, masked_proof) = mask(&mut rng, &joint_pk, card, &Fr::one()).unwrap();
        verify_mask(&joint_pk, card, &masked_card, &masked_proof).unwrap();

        deck.push(masked_card)
    }

    let mut prover_params = PROVER_PARAMS.lock().unwrap();
    refresh_prover_params_public_key(&mut prover_params, &joint_pk).unwrap();

    let mut verifier_params = get_shuffle_verifier_params().unwrap();
    verifier_params.verifier_params = prover_params.prover_params.verifier_params.clone();

    // Alice, start shuffling.
    let (proof, alice_shuffle_deck) =
        prove_shuffle(&mut rng, &joint_pk, &deck, &prover_params).unwrap();
    verify_shuffle(&verifier_params, &deck, &alice_shuffle_deck, &proof).unwrap();

    // Bob, start shuffling.
    let (proof, bob_shuffle_deck) =
        prove_shuffle(&mut rng, &joint_pk, &alice_shuffle_deck, &prover_params).unwrap();
    verify_shuffle(
        &verifier_params,
        &alice_shuffle_deck,
        &bob_shuffle_deck,
        &proof,
    )
    .unwrap();

    // Charlie, start shuffling.
    let (proof, charlie_shuffle_deck) =
        prove_shuffle(&mut rng, &joint_pk, &bob_shuffle_deck, &prover_params).unwrap();
    verify_shuffle(
        &verifier_params,
        &bob_shuffle_deck,
        &charlie_shuffle_deck,
        &proof,
    )
    .unwrap();

    // David, start shuffling.
    let (proof, david_shuffle_deck) =
        prove_shuffle(&mut rng, &joint_pk, &charlie_shuffle_deck, &prover_params).unwrap();
    verify_shuffle(
        &verifier_params,
        &charlie_shuffle_deck,
        &david_shuffle_deck,
        &proof,
    )
    .unwrap();

    // Set last deck to player
    let last_deck = david_shuffle_deck;
    alice.set_deck(&last_deck);
    bob.set_deck(&last_deck);
    charlie.set_deck(&last_deck);
    david.set_deck(&last_deck);

    // Distribute and reveal
    for round in last_deck.chunks(4) {
        let a_card = &round[0];
        let b_card = &round[1];
        let c_card = &round[2];
        let d_card = &round[3];

        // reveal a_card
        let (a_re_b, a_re_b_proof, b_pk) = bob.compute_reveal(&mut rng, a_card);
        let (a_re_c, a_re_c_proof, c_pk) = charlie.compute_reveal(&mut rng, a_card);
        let (a_re_d, a_re_d_proof, d_pk) = david.compute_reveal(&mut rng, a_card);
        verify_reveal(&b_pk, a_card, &a_re_b, &a_re_b_proof).unwrap();
        verify_reveal(&c_pk, a_card, &a_re_c, &a_re_c_proof).unwrap();
        verify_reveal(&d_pk, a_card, &a_re_d, &a_re_d_proof).unwrap();
        let a_reveals = vec![a_re_b, a_re_c, a_re_d];
        let real_a_card = alice.unmask(&mut rng, a_reveals, &card_mapping, a_card);
        println!("Alice: {:?}", real_a_card);

        // reveal b_card
        let (b_re_a, b_re_a_proof, a_pk) = alice.compute_reveal(&mut rng, b_card);
        let (b_re_c, b_re_c_proof, c_pk) = charlie.compute_reveal(&mut rng, b_card);
        let (b_re_d, b_re_d_proof, d_pk) = david.compute_reveal(&mut rng, b_card);
        verify_reveal(&a_pk, b_card, &b_re_a, &b_re_a_proof).unwrap();
        verify_reveal(&c_pk, b_card, &b_re_c, &b_re_c_proof).unwrap();
        verify_reveal(&d_pk, b_card, &b_re_d, &b_re_d_proof).unwrap();
        let b_reveals = vec![b_re_a, b_re_c, b_re_d];
        let real_b_card = bob.unmask(&mut rng, b_reveals, &card_mapping, b_card);
        println!("Bob: {:?}", real_b_card);

        // reveal c_card
        let (c_re_b, c_re_b_proof, b_pk) = bob.compute_reveal(&mut rng, c_card);
        let (c_re_a, c_re_a_proof, a_pk) = alice.compute_reveal(&mut rng, c_card);
        let (c_re_d, c_re_d_proof, d_pk) = david.compute_reveal(&mut rng, c_card);
        verify_reveal(&b_pk, c_card, &c_re_b, &c_re_b_proof).unwrap();
        verify_reveal(&a_pk, c_card, &c_re_a, &c_re_a_proof).unwrap();
        verify_reveal(&d_pk, c_card, &c_re_d, &c_re_d_proof).unwrap();
        let c_reveals = vec![c_re_b, c_re_a, c_re_d];
        let real_c_card = charlie.unmask(&mut rng, c_reveals, &card_mapping, c_card);
        println!("Charlie: {:?}", real_c_card);

        // reveal d_card
        let (d_re_b, d_re_b_proof, b_pk) = bob.compute_reveal(&mut rng, d_card);
        let (d_re_c, d_re_c_proof, c_pk) = charlie.compute_reveal(&mut rng, d_card);
        let (d_re_a, d_re_a_proof, a_pk) = alice.compute_reveal(&mut rng, d_card);
        verify_reveal(&b_pk, d_card, &d_re_b, &d_re_b_proof).unwrap();
        verify_reveal(&c_pk, d_card, &d_re_c, &d_re_c_proof).unwrap();
        verify_reveal(&a_pk, d_card, &d_re_a, &d_re_a_proof).unwrap();
        let d_reveals = vec![d_re_b, d_re_c, d_re_a];
        let real_d_card = david.unmask(&mut rng, d_reveals, &card_mapping, d_card);
        println!("David: {:?}", real_d_card);
    }
}
