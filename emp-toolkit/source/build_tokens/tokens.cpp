#include "tokens.h"
#include "tokens-misc.h"
#include "ecdsa.h"
#include "emp-sh2pc/emp-sh2pc.h"

#define MERCH ALICE
#define CUST BOB

using namespace emp;

// TODO: add fail bit and count up all the validations
void issue_tokens() {
  // check old pay token
  verify_token_sig();

  // make sure wallets are well-formed
  compare_wallets();
  
  // make sure customer committed to this new wallet
  open_commitment();

  // make sure new close transactions are well-formed
  validate_transactions();

  // sign new close transactions 
  // TODO: update ecdsa signature API to take secret params
  int skc = 0;
  int kic = 0;
  int mc  = 0;
  struct ECDSA_sig signed_merch_tx = ecdsa_sign(skc, kic, mc);
  struct ECDSA_sig signed_escrow_tx = ecdsa_sign(skc, kic, mc);

  // sign new pay token
  sign_token();

  // mask pay and close tokens
  mask_token(); // pay token
  mask_token(); // close token - merchant close
  mask_token(); // close token - escrow close

  // ...return masked tokens
}

/* customer's token generation function
 *
 * runs MPC to compute masked tokens (close- and pay-).
 * blocks until computation is finished.
 *
 * Assumes close_tx_escrow and close_tx_merch are padded to 
 * exactly 1024 bits according to the SHA256 spec.
 */
void build_masked_tokens_cust(
  PubKey pkM,
  bool *amount,
  bool *com_new,
  RevLock rl_old,
  int port,
  string ip_addr,

  State w_new,
  State w_old,
  bool *t,
  bool *pt_old,
  bool close_tx_escrow[1024],
  bool close_tx_merch[1024],

  int *ct_masked,
  int *pt_masked
) {
  
  // todo: replace new/delete with sweet auto
  NetIO * io = new NetIO("127.0.0.1", port);
  setup_semi_honest(io, CUST);

  issue_tokens();

  delete io;
}

void build_masked_tokens_merch(
  PubKey pkM,
  bool *amount,
  bool *com_new,
  RevLock rl_old,
  int port,
  string ip_addr,

  bool *close_mask,
  bool *pay_mask,
  EcdsaPartialSig sig1,
  EcdsaPartialSig sig2,
  EcdsaPartialSig sig3
) {

  // todo: replace new/delete with sweet auto
  NetIO * io = new NetIO(nullptr, port);
  setup_semi_honest(io, MERCH);

  issue_tokens();

  delete io;
}

void sign_token() {

}

Bit verify_token_sig() {
  Bit b;
  return b;
}

// make sure wallets are well-formed
Bit compare_wallets() {
  Bit b;
  return b;
}

// make sure customer committed to this new wallet
Bit open_commitment() {
  Bit b;
  return b;
}

// make sure new close transactions are well-formed
Bit validate_transactions() {
  Bit b;
  return b;
}

// mask pay and close tokens
void mask_token() {

}
