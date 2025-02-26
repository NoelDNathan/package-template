use barnett_smart_card_protocol::discrete_log_cards;
use barnett_smart_card_protocol::BarnettSmartProtocol;

use anyhow;
use ark_ff::{to_bytes, UniformRand};
use ark_std::{rand::Rng, One};
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
use rand::thread_rng;
use std::collections::HashMap;
use std::iter::Iterator;
use thiserror::Error;

// Choose elliptic curve setting
type Curve = starknet_curve::Projective;
type Scalar = starknet_curve::Fr;

// Instantiate concrete type for our card protocol
type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;
type CardParameters = discrete_log_cards::Parameters<Curve>;
type PublicKey = discrete_log_cards::PublicKey<Curve>;
type SecretKey = discrete_log_cards::PlayerSecretKey<Curve>;

type Card = discrete_log_cards::Card<Curve>;
type MaskedCard = discrete_log_cards::MaskedCard<Curve>;
type RevealToken = discrete_log_cards::RevealToken<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;

#[derive(Error, Debug, PartialEq)]
pub enum GameErrors {
    #[error("No such card in hand")]
    CardNotFound,

    #[error("Invalid card")]
    InvalidCard,
}

#[derive(PartialEq, Clone, Copy, Eq)]
pub enum Suite {
    Club,
    Diamond,
    Heart,
    Spade,
}

impl Suite {
    const VALUES: [Self; 4] = [Self::Club, Self::Diamond, Self::Heart, Self::Spade];
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

        write!(f, "{}{}", val, suite)
    }
}

#[derive(Clone)]
struct Player {
    name: Vec<u8>,
    sk: SecretKey,
    pk: PublicKey,
    proof_key: ProofKeyOwnership,
    cards: Vec<MaskedCard>,
    opened_cards: Vec<Option<ClassicPlayingCard>>,
}

impl Player {
    pub fn new<R: Rng>(rng: &mut R, pp: &CardParameters, name: &Vec<u8>) -> anyhow::Result<Self> {
        let (pk, sk) = CardProtocol::player_keygen(rng, pp)?;
        let proof_key = CardProtocol::prove_key_ownership(rng, pp, &pk, &sk, name)?;
        Ok(Self {
            name: name.clone(),
            sk,
            pk,
            proof_key,
            cards: vec![],
            opened_cards: vec![],
        })
    }

    pub fn receive_card(&mut self, card: MaskedCard) {
        self.cards.push(card);
        self.opened_cards.push(None);
    }

    pub fn peek_at_card(
        &mut self,
        parameters: &CardParameters,
        reveal_tokens: &mut Vec<(RevealToken, RevealProof, PublicKey)>,
        card_mappings: &HashMap<Card, ClassicPlayingCard>,
        card: &MaskedCard,
    ) -> Result<(), anyhow::Error> {
        let i = self.cards.iter().position(|&x| x == *card);

        let i = i.ok_or(GameErrors::CardNotFound)?;

        //TODO add function to create that without the proof
        let rng = &mut thread_rng();
        let own_reveal_token = self.compute_reveal_token(rng, parameters, card)?;
        reveal_tokens.push(own_reveal_token);

        let unmasked_card = CardProtocol::unmask(&parameters, reveal_tokens, card)?;
        let opened_card = card_mappings.get(&unmasked_card);
        let opened_card = opened_card.ok_or(GameErrors::InvalidCard)?;

        self.opened_cards[i] = Some(*opened_card);
        Ok(())
    }

    pub fn compute_reveal_token<R: Rng>(
        &self,
        rng: &mut R,
        pp: &CardParameters,
        card: &MaskedCard,
    ) -> anyhow::Result<(RevealToken, RevealProof, PublicKey)> {
        let (reveal_token, reveal_proof) =
            CardProtocol::compute_reveal_token(rng, &pp, &self.sk, &self.pk, card)?;

        Ok((reveal_token, reveal_proof, self.pk))
    }
}

//Every player will have to calculate this function for cards that are in play
pub fn open_card(
    parameters: &CardParameters,
    reveal_tokens: &Vec<(RevealToken, RevealProof, PublicKey)>,
    card_mappings: &HashMap<Card, ClassicPlayingCard>,
    card: &MaskedCard,
) -> Result<ClassicPlayingCard, anyhow::Error> {
    let unmasked_card = CardProtocol::unmask(&parameters, reveal_tokens, card)?;
    let opened_card = card_mappings.get(&unmasked_card);
    let opened_card = opened_card.ok_or(GameErrors::InvalidCard)?;

    Ok(*opened_card)
}

fn encode_cards<R: Rng>(rng: &mut R, num_of_cards: usize) -> HashMap<Card, ClassicPlayingCard> {
    let mut map: HashMap<Card, ClassicPlayingCard> = HashMap::new();
    let plaintexts = (0..num_of_cards)
        .map(|_| Card::rand(rng))
        .collect::<Vec<_>>();

    let mut i = 0;
    for value in Value::VALUES.iter().copied() {
        for suite in Suite::VALUES.iter().copied() {
            let current_card = ClassicPlayingCard::new(value, suite);
            map.insert(plaintexts[i], current_card);
            i += 1;
        }
    }

    map
}

fn main() -> anyhow::Result<()> {
    let m = 2;
    let n = 26;
    let num_of_cards = m * n;
    let rng = &mut thread_rng();

    let parameters = CardProtocol::setup(rng, m, n)?;
    let card_mapping = encode_cards(rng, num_of_cards);

    let mut andrija = Player::new(rng, &parameters, &to_bytes![b"Andrija"].unwrap())?;
    let mut kobi = Player::new(rng, &parameters, &to_bytes![b"Kobi"].unwrap())?;
    let mut nico = Player::new(rng, &parameters, &to_bytes![b"Nico"].unwrap())?;
    let mut tom = Player::new(rng, &parameters, &to_bytes![b"Tom"].unwrap())?;

    let players = vec![andrija.clone(), kobi.clone(), nico.clone(), tom.clone()];

    // Crear una variable para las cartas comunitarias
    let mut community_cards: Vec<MaskedCard> = Vec::new();
    
    let key_proof_info = players
        .iter()
        .map(|p| (p.pk, p.proof_key, p.name.clone()))
        .collect::<Vec<_>>();

    // Each player should run this computation. Alternatively, it can be ran by a smart contract
    let joint_pk = CardProtocol::compute_aggregate_key(&parameters, &key_proof_info)?;

    // Each player should run this computation and verify that all players agree on the initial deck
    let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = card_mapping
        .keys()
        .map(|card| CardProtocol::mask(rng, &parameters, &joint_pk, &card, &Scalar::one()))
        .collect::<Result<Vec<_>, _>>()?;

    let deck = deck_and_proofs
        .iter()
        .map(|x| x.0)
        .collect::<Vec<MaskedCard>>();

    
        
    // SHUFFLE TIME --------------
    // 1.a Andrija shuffles first
    let permutation = Permutation::new(rng, m * n);
    let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

    let (a_shuffled_deck, a_shuffle_proof) = CardProtocol::shuffle_and_remask(
        rng,
        &parameters,
        &joint_pk,
        &deck,
        &masking_factors,
        &permutation,
    )?;

    // 1.b everyone checks!
    CardProtocol::verify_shuffle(
        &parameters,
        &joint_pk,
        &deck,
        &a_shuffled_deck,
        &a_shuffle_proof,
    )?;

    //2.a Kobi shuffles second
    let permutation = Permutation::new(rng, m * n);
    let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

    let (k_shuffled_deck, k_shuffle_proof) = CardProtocol::shuffle_and_remask(
        rng,
        &parameters,
        &joint_pk,
        &a_shuffled_deck,
        &masking_factors,
        &permutation,
    )?;

    //2.b Everyone checks
    CardProtocol::verify_shuffle(
        &parameters,
        &joint_pk,
        &a_shuffled_deck,
        &k_shuffled_deck,
        &k_shuffle_proof,
    )?;

    //3.a Nico shuffles third
    let permutation = Permutation::new(rng, m * n);
    let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

    let (n_shuffled_deck, n_shuffle_proof) = CardProtocol::shuffle_and_remask(
        rng,
        &parameters,
        &joint_pk,
        &k_shuffled_deck,
        &masking_factors,
        &permutation,
    )?;

    //3.b Everyone checks
    CardProtocol::verify_shuffle(
        &parameters,
        &joint_pk,
        &k_shuffled_deck,
        &n_shuffled_deck,
        &n_shuffle_proof,
    )?;

    //4.a Tom shuffles last
    let permutation = Permutation::new(rng, m * n);
    let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

    let (final_shuffled_deck, final_shuffle_proof) = CardProtocol::shuffle_and_remask(
        rng,
        &parameters,
        &joint_pk,
        &n_shuffled_deck,
        &masking_factors,
        &permutation,
    )?;

    //4.b Everyone checks before accepting last deck for game
    CardProtocol::verify_shuffle(
        &parameters,
        &joint_pk,
        &n_shuffled_deck,
        &final_shuffled_deck,
        &final_shuffle_proof,
    )?;

    // CARDS ARE SHUFFLED. ROUND OF THE GAME CAN BEGIN
    let deck = final_shuffled_deck;

    // Each player receives two cards

    andrija.receive_card(deck[0]);
    andrija.receive_card(deck[1]);

    kobi.receive_card(deck[2]);
    kobi.receive_card(deck[3]);

    nico.receive_card(deck[4]);
    nico.receive_card(deck[5]);

    tom.receive_card(deck[6]);
    tom.receive_card(deck[7]);

    // El flop: 3 cartas comunitarias
    community_cards.push(deck[8]);
    community_cards.push(deck[9]);
    community_cards.push(deck[10]);

    // El turn: 1 carta comunitaria
    community_cards.push(deck[11]);

    // El river: 1 carta comunitaria
    community_cards.push(deck[12]);



    
    // Flop: las primeras tres cartas comunitarias
    let flop = vec![deck[8], deck[9], deck[10]];
    let mut flop_reveal_tokens = Vec::new();
    for card in &flop {
        flop_reveal_tokens.push(andrija.compute_reveal_token(rng, &parameters, card)?);
        flop_reveal_tokens.push(kobi.compute_reveal_token(rng, &parameters, card)?);
        flop_reveal_tokens.push(nico.compute_reveal_token(rng, &parameters, card)?);
        flop_reveal_tokens.push(tom.compute_reveal_token(rng, &parameters, card)?);
    }

    let mut flop_reveal_tokens1 = Vec::new();
    flop_reveal_tokens1.push(andrija.compute_reveal_token(rng, &parameters, &deck[8])?);
    flop_reveal_tokens1.push(kobi.compute_reveal_token(rng, &parameters, &deck[8])?);
    flop_reveal_tokens1.push(nico.compute_reveal_token(rng, &parameters, &deck[8])?);
    flop_reveal_tokens1.push(tom.compute_reveal_token(rng, &parameters, &deck[8])?);

    let mut flop_reveal_tokens2 = Vec::new();
    flop_reveal_tokens2.push(andrija.compute_reveal_token(rng, &parameters, &deck[9])?);
    flop_reveal_tokens2.push(kobi.compute_reveal_token(rng, &parameters, &deck[9])?);
    flop_reveal_tokens2.push(nico.compute_reveal_token(rng, &parameters, &deck[9])?);
    flop_reveal_tokens2.push(tom.compute_reveal_token(rng, &parameters, &deck[9])?);

    let mut flop_reveal_tokens3 = Vec::new();
    flop_reveal_tokens3.push(andrija.compute_reveal_token(rng, &parameters, &deck[10])?);
    flop_reveal_tokens3.push(kobi.compute_reveal_token(rng, &parameters, &deck[10])?);
    flop_reveal_tokens3.push(nico.compute_reveal_token(rng, &parameters, &deck[10])?);
    flop_reveal_tokens3.push(tom.compute_reveal_token(rng, &parameters, &deck[10])?);




    // Turn: la cuarta carta comunitaria
    let turn = vec![deck[11]];
    let mut turn_reveal_tokens = Vec::new();
    for card in &turn {
        turn_reveal_tokens.push(andrija.compute_reveal_token(rng, &parameters, card)?);
        turn_reveal_tokens.push(kobi.compute_reveal_token(rng, &parameters, card)?);
        turn_reveal_tokens.push(nico.compute_reveal_token(rng, &parameters, card)?);
        turn_reveal_tokens.push(tom.compute_reveal_token(rng, &parameters, card)?);
    }


    // River: la quinta carta comunitaria
    let river = vec![deck[12]];
    let mut river_reveal_tokens = Vec::new();
    for card in &river {
        river_reveal_tokens.push(andrija.compute_reveal_token(rng, &parameters, card)?);
        river_reveal_tokens.push(kobi.compute_reveal_token(rng, &parameters, card)?);
        river_reveal_tokens.push(nico.compute_reveal_token(rng, &parameters, card)?);
        river_reveal_tokens.push(tom.compute_reveal_token(rng, &parameters, card)?);
    }

    let andrija_rt_2 = andrija.compute_reveal_token(rng, &parameters, &deck[2])?;
    let andrija_rt_3 = andrija.compute_reveal_token(rng, &parameters, &deck[3])?;
    let andrija_rt_4 = andrija.compute_reveal_token(rng, &parameters, &deck[4])?;
    let andrija_rt_5 = andrija.compute_reveal_token(rng, &parameters, &deck[5])?;
    let andrija_rt_6 = andrija.compute_reveal_token(rng, &parameters, &deck[6])?;
    let andrija_rt_7 = andrija.compute_reveal_token(rng, &parameters, &deck[7])?;
    
    let kobi_rt_0 = kobi.compute_reveal_token(rng, &parameters, &deck[0])?;
    let kobi_rt_1 = kobi.compute_reveal_token(rng, &parameters, &deck[1])?;
    let kobi_rt_4 = kobi.compute_reveal_token(rng, &parameters, &deck[4])?;
    let kobi_rt_5 = kobi.compute_reveal_token(rng, &parameters, &deck[5])?;
    let kobi_rt_6 = kobi.compute_reveal_token(rng, &parameters, &deck[6])?;
    let kobi_rt_7 = kobi.compute_reveal_token(rng, &parameters, &deck[7])?;

    let nico_rt_0 = nico.compute_reveal_token(rng, &parameters, &deck[0])?;
    let nico_rt_1 = nico.compute_reveal_token(rng, &parameters, &deck[1])?;
    let nico_rt_2 = nico.compute_reveal_token(rng, &parameters, &deck[2])?;
    let nico_rt_3 = nico.compute_reveal_token(rng, &parameters, &deck[3])?;
    let nico_rt_6 = nico.compute_reveal_token(rng, &parameters, &deck[6])?;
    let nico_rt_7 = nico.compute_reveal_token(rng, &parameters, &deck[7])?;

    let tom_rt_0 = tom.compute_reveal_token(rng, &parameters, &deck[0])?;
    let tom_rt_1 = tom.compute_reveal_token(rng, &parameters, &deck[1])?;
    let tom_rt_2 = tom.compute_reveal_token(rng, &parameters, &deck[2])?;
    let tom_rt_3 = tom.compute_reveal_token(rng, &parameters, &deck[3])?;
    let tom_rt_4 = tom.compute_reveal_token(rng, &parameters, &deck[4])?;
    let tom_rt_5 = tom.compute_reveal_token(rng, &parameters, &deck[5])?;

    let mut rts_andrija0 = vec![kobi_rt_0, nico_rt_0, tom_rt_0];
    let mut rts_andrija1 = vec![kobi_rt_1, nico_rt_1, tom_rt_1];
    let mut rts_kobi2 = vec![andrija_rt_2, nico_rt_2, tom_rt_2];
    let mut rts_kobi3 = vec![andrija_rt_3, nico_rt_3, tom_rt_3];
    let mut rts_nico4 = vec![andrija_rt_4, kobi_rt_4, tom_rt_4];
    let mut rts_nico5 = vec![andrija_rt_5, kobi_rt_5, tom_rt_5];
    let mut rts_tom6 = vec![andrija_rt_6, kobi_rt_6, nico_rt_6];
    let mut rts_tom7 = vec![andrija_rt_7, kobi_rt_7, nico_rt_7];

    //At this moment players privately open their cards and only they know that values
    andrija.peek_at_card(&parameters, &mut rts_andrija0, &card_mapping, &deck[0])?;
    andrija.peek_at_card(&parameters, &mut rts_andrija1, &card_mapping, &deck[1])?;
    kobi.peek_at_card(&parameters, &mut rts_kobi2, &card_mapping, &deck[2])?;
    kobi.peek_at_card(&parameters, &mut rts_kobi3, &card_mapping, &deck[3])?;
    nico.peek_at_card(&parameters, &mut rts_nico4, &card_mapping, &deck[4])?;
    nico.peek_at_card(&parameters, &mut rts_nico5, &card_mapping, &deck[5])?;
    tom.peek_at_card(&parameters, &mut rts_tom6, &card_mapping, &deck[6])?;
    tom.peek_at_card(&parameters, &mut rts_tom7, &card_mapping, &deck[7])?;

    /* Here we can add custom logic of a game:
        1. swap card
        2. place a bet
        3. ...
    */

    //At this moment players reveal their cards to each other and everything becomes public

    //1.a everyone reveals the secret for their card
    let andrija_rt_0 = andrija.compute_reveal_token(rng, &parameters, &deck[0])?;
    let andrija_rt_1 = andrija.compute_reveal_token(rng, &parameters, &deck[1])?;
    let kobi_rt_2 = kobi.compute_reveal_token(rng, &parameters, &deck[2])?;
    let kobi_rt_3 = kobi.compute_reveal_token(rng, &parameters, &deck[3])?;
    let nico_rt_4 = nico.compute_reveal_token(rng, &parameters, &deck[4])?;
    let nico_rt_5 = nico.compute_reveal_token(rng, &parameters, &deck[5])?;
    let tom_rt_6 = tom.compute_reveal_token(rng, &parameters, &deck[6])?;
    let tom_rt_7 = tom.compute_reveal_token(rng, &parameters, &deck[7])?;

    //2. tokens for all other cards are exchanged
    //TODO add struct for this so that we can just clone

    let andrija_rt_2 = andrija.compute_reveal_token(rng, &parameters, &deck[2])?;
    let andrija_rt_3 = andrija.compute_reveal_token(rng, &parameters, &deck[3])?;
    let andrija_rt_4 = andrija.compute_reveal_token(rng, &parameters, &deck[4])?;
    let andrija_rt_5 = andrija.compute_reveal_token(rng, &parameters, &deck[5])?;
    let andrija_rt_6 = andrija.compute_reveal_token(rng, &parameters, &deck[6])?;
    let andrija_rt_7 = andrija.compute_reveal_token(rng, &parameters, &deck[7])?;
    
    let kobi_rt_0 = kobi.compute_reveal_token(rng, &parameters, &deck[0])?;
    let kobi_rt_1 = kobi.compute_reveal_token(rng, &parameters, &deck[1])?;
    let kobi_rt_4 = kobi.compute_reveal_token(rng, &parameters, &deck[4])?;
    let kobi_rt_5 = kobi.compute_reveal_token(rng, &parameters, &deck[5])?;
    let kobi_rt_6 = kobi.compute_reveal_token(rng, &parameters, &deck[6])?;
    let kobi_rt_7 = kobi.compute_reveal_token(rng, &parameters, &deck[7])?;

    let nico_rt_0 = nico.compute_reveal_token(rng, &parameters, &deck[0])?;
    let nico_rt_1 = nico.compute_reveal_token(rng, &parameters, &deck[1])?;
    let nico_rt_2 = nico.compute_reveal_token(rng, &parameters, &deck[2])?;
    let nico_rt_3 = nico.compute_reveal_token(rng, &parameters, &deck[3])?;
    let nico_rt_6 = nico.compute_reveal_token(rng, &parameters, &deck[6])?;
    let nico_rt_7 = nico.compute_reveal_token(rng, &parameters, &deck[7])?;

    let tom_rt_0 = tom.compute_reveal_token(rng, &parameters, &deck[0])?;
    let tom_rt_1 = tom.compute_reveal_token(rng, &parameters, &deck[1])?;
    let tom_rt_2 = tom.compute_reveal_token(rng, &parameters, &deck[2])?;
    let tom_rt_3 = tom.compute_reveal_token(rng, &parameters, &deck[3])?;
    let tom_rt_4 = tom.compute_reveal_token(rng, &parameters, &deck[4])?;
    let tom_rt_5 = tom.compute_reveal_token(rng, &parameters, &deck[5])?;

    let rt_0 = vec![andrija_rt_0, kobi_rt_0, nico_rt_0, tom_rt_0];
    let rt_1 = vec![andrija_rt_1, kobi_rt_1, nico_rt_1, tom_rt_1];
    let rt_2 = vec![andrija_rt_2, kobi_rt_2, nico_rt_2, tom_rt_2];
    let rt_3 = vec![andrija_rt_3, kobi_rt_3, nico_rt_3, tom_rt_3];
    let rt_4 = vec![andrija_rt_4, kobi_rt_4, nico_rt_4, tom_rt_4];
    let rt_5 = vec![andrija_rt_5, kobi_rt_5, nico_rt_5, tom_rt_5];
    let rt_6 = vec![andrija_rt_6, kobi_rt_6, nico_rt_6, tom_rt_6];
    let rt_7 = vec![andrija_rt_7, kobi_rt_7, nico_rt_7, tom_rt_7];

    //Everyone computes for each card (except for their own card):
    let andrija_card1 = open_card(&parameters, &rt_0, &card_mapping, &deck[0])?;
    let andrija_card2 = open_card(&parameters, &rt_1, &card_mapping, &deck[1])?;
    let kobi_card1 = open_card(&parameters, &rt_2, &card_mapping, &deck[2])?;
    let kobi_card2 = open_card(&parameters, &rt_3, &card_mapping, &deck[3])?;
    let nico_card1 = open_card(&parameters, &rt_4, &card_mapping, &deck[4])?;
    let nico_card2 = open_card(&parameters, &rt_5, &card_mapping, &deck[5])?;
    let tom_card1 = open_card(&parameters, &rt_6, &card_mapping, &deck[6])?;
    let tom_card2 = open_card(&parameters, &rt_7, &card_mapping, &deck[7])?;
    
    let cm_card1 = open_card(&parameters, &flop_reveal_tokens1, &card_mapping, &deck[8])?;
    let cm_card2 = open_card(&parameters, &flop_reveal_tokens2, &card_mapping, &deck[9])?;
    let cm_card3 = open_card(&parameters, &flop_reveal_tokens3, &card_mapping, &deck[10])?;
    let cm_card4 = open_card(&parameters, &turn_reveal_tokens, &card_mapping, &deck[11])?;
    let cm_card5 = open_card(&parameters, &river_reveal_tokens, &card_mapping, &deck[12])?;

    println!("Andrija cards: {:?}, {:?}", andrija_card1, andrija_card2);
    println!("Kobi cards: {:?}, {:?}", kobi_card1, kobi_card2);
    println!("Nico cards: {:?}, {:?}", nico_card1, nico_card2);
    println!("Tom cards: {:?}, {:?}", tom_card1, tom_card2);
    
    println!("Community Cards: {:?} {:?} {:?} {:?} {:?}", cm_card1, cm_card2, cm_card3, cm_card4, cm_card5);
    // println!("Community Cards: {:?} {:?}", cm_card4, cm_card5);

    Ok(())
}
