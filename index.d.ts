/* tslint:disable */
/* eslint-disable */

/* auto-generated by NAPI-RS */

export declare function setupProtocol(m: number, n: number): number
export declare class Player {
  static new(rng: R, pp: CardParameters, name: Array<number>): Player
  receiveCard(card: MaskedCard): void
  peekAtCard(parameters: CardParameters, revealTokens: Array<[RevealToken, RevealProof, PublicKey]>, cardMappings: Record<Card, ClassicPlayingCard>, card: MaskedCard): void
  computeRevealToken(rng: R, pp: CardParameters, card: MaskedCard): [RevealToken, RevealProof, PublicKey]
}
