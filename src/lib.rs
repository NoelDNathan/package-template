use anyhow;
// use ark_ff::{to_bytes, UniformRand};
use ark_std::{rand::Rng, One};
use barnett_smart_protocol::discrete_log_cards;
use barnett_smart_protocol::BarnettSmartProtocol;
// use napi::bindgen_prelude::*;
// use napi_derive::napi;
// use proof_essentials::utils::permutation::Permutation;
// use proof_essentials::utils::rand::sample_vector;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
use rand::thread_rng;
use std::collections::HashMap;
// use std::iter::Iterator;
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

pub fn setup_protocol(m: u32, n: u32) -> u32 {
  m * n
}

#[derive(Clone)] // Derivamos Clone para la estructura
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
