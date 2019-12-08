#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens-misc.h"

HMACKey_d distribute_HMACKey(HMACKey_l key){

  HMACKey_d to_return;
  to_return.key[0] = Integer(32, key.key[0], PUBLIC);
  to_return.key[1] = Integer(32, key.key[1], PUBLIC);
  to_return.key[2] = Integer(32, key.key[2], PUBLIC);
  to_return.key[3] = Integer(32, key.key[3], PUBLIC);
  to_return.key[4] = Integer(32, key.key[4], PUBLIC);
  to_return.key[5] = Integer(32, key.key[5], PUBLIC);
  to_return.key[6] = Integer(32, key.key[6], PUBLIC);
  to_return.key[7] = Integer(32, key.key[7], PUBLIC);
  to_return.key[8] = Integer(32, key.key[8], PUBLIC);
  to_return.key[9] = Integer(32, key.key[9], PUBLIC);
  to_return.key[10] = Integer(32, key.key[10], PUBLIC);
  to_return.key[11] = Integer(32, key.key[11], PUBLIC);
  to_return.key[12] = Integer(32, key.key[12], PUBLIC);
  to_return.key[13] = Integer(32, key.key[13], PUBLIC);
  to_return.key[14] = Integer(32, key.key[14], PUBLIC);
  to_return.key[15] = Integer(32, key.key[15], PUBLIC);

  return to_return;
}

HMACKey_l localize_HMACKey(HMACKey_d key){
  HMACKey_l to_return;
  // GABE TODO
  
  return to_return;
}

RevLock_d distribute_RevLock(RevLock_l revlock){

  RevLock_d to_return;
  to_return.revlock[0] = Integer(32, revlock.revlock[0], PUBLIC);
  to_return.revlock[1] = Integer(32, revlock.revlock[1], PUBLIC);
  to_return.revlock[2] = Integer(32, revlock.revlock[2], PUBLIC);
  to_return.revlock[3] = Integer(32, revlock.revlock[3], PUBLIC);
  to_return.revlock[4] = Integer(32, revlock.revlock[4], PUBLIC);
  to_return.revlock[5] = Integer(32, revlock.revlock[5], PUBLIC);
  to_return.revlock[6] = Integer(32, revlock.revlock[6], PUBLIC);
  to_return.revlock[7] = Integer(32, revlock.revlock[7], PUBLIC);

  return to_return;
}

RevLock_l localize_RevLock(RevLock_d revlock){
  RevLock_l to_return;
  // GABE TODO

  return to_return;
}

PayToken_d distribute_PayToken(PayToken_l paytoken){

  PayToken_d to_return;
  to_return.paytoken[0] = Integer(32, paytoken.paytoken[0], PUBLIC);
  to_return.paytoken[1] = Integer(32, paytoken.paytoken[1], PUBLIC);
  to_return.paytoken[2] = Integer(32, paytoken.paytoken[2], PUBLIC);
  to_return.paytoken[3] = Integer(32, paytoken.paytoken[3], PUBLIC);
  to_return.paytoken[4] = Integer(32, paytoken.paytoken[4], PUBLIC);
  to_return.paytoken[5] = Integer(32, paytoken.paytoken[5], PUBLIC);
  to_return.paytoken[6] = Integer(32, paytoken.paytoken[6], PUBLIC);
  to_return.paytoken[7] = Integer(32, paytoken.paytoken[7], PUBLIC);

  return to_return;
}

PayToken_l localize_PayToken(PayToken_d paytoken){
  PayToken_l to_return;
  // GABE TODO

  return to_return;
}

Nonce_d distribute_Nonce(Nonce_l nonce) {

  Nonce_d to_return;
  to_return.nonce[0] = Integer(32, nonce.nonce[0], PUBLIC);
  to_return.nonce[1] = Integer(32, nonce.nonce[1], PUBLIC);
  to_return.nonce[2] = Integer(32, nonce.nonce[2], PUBLIC);

  return to_return;
}

Nonce_l localize_Nonce(Nonce_d nonce) {
  Nonce_l to_return;
  // GABE TODO

  return to_return;
}

State_d distribute_State(State_l state){

  State_d to_return;

  to_return.nonce = distribute_Nonce(state.nonce);
  to_return.rl = distribute_RevLock(state.rl);
  to_return.balance_cust = Integer(32, state.balance_cust, PUBLIC);
  to_return.balance_merch = Integer(32, state.balance_merch, PUBLIC);

  to_return.txid_merch[0] = Integer(32, state.txid_merch[0], PUBLIC);
  to_return.txid_merch[1] = Integer(32, state.txid_merch[1], PUBLIC);
  to_return.txid_merch[2] = Integer(32, state.txid_merch[2], PUBLIC);
  to_return.txid_merch[3] = Integer(32, state.txid_merch[3], PUBLIC);
  to_return.txid_merch[4] = Integer(32, state.txid_merch[4], PUBLIC);
  to_return.txid_merch[5] = Integer(32, state.txid_merch[5], PUBLIC);
  to_return.txid_merch[6] = Integer(32, state.txid_merch[6], PUBLIC);
  to_return.txid_merch[7] = Integer(32, state.txid_merch[7], PUBLIC);

  to_return.txid_escrow[0] = Integer(32, state.txid_escrow[0], PUBLIC);
  to_return.txid_escrow[1] = Integer(32, state.txid_escrow[1], PUBLIC);
  to_return.txid_escrow[2] = Integer(32, state.txid_escrow[2], PUBLIC);
  to_return.txid_escrow[3] = Integer(32, state.txid_escrow[3], PUBLIC);
  to_return.txid_escrow[4] = Integer(32, state.txid_escrow[4], PUBLIC);
  to_return.txid_escrow[5] = Integer(32, state.txid_escrow[5], PUBLIC);
  to_return.txid_escrow[6] = Integer(32, state.txid_escrow[6], PUBLIC);
  to_return.txid_escrow[7] = Integer(32, state.txid_escrow[7], PUBLIC);

  return to_return;
}

State_l localize_State(State_d state){
  State_l to_return;
  // GABE TODO

  return to_return;
}

EcdsaPartialSig_d distribute_EcdsaPartialSig(EcdsaPartialSig_l psl){
  EcdsaPartialSig_d to_return;
  // GABE TODO
  to_return.r = Integer(257, psl.r, MERCH);
  to_return.k_inv = Integer(513, psl.k_inv, MERCH);

  return to_return;
}

// honestly, if we ever need to do this (which we shouldn't outside of testing)
// we definitely should not reveal them publicly.
EcdsaPartialSig_l localize_EcdsaPartialSig(EcdsaPartialSig_d psd){
  EcdsaPartialSig_l to_return;

  to_return.r = psd.r.reveal<string>(PUBLIC);
  to_return.k_inv = psd.k_inv.reveal<string>(PUBLIC);

  return to_return;
}
