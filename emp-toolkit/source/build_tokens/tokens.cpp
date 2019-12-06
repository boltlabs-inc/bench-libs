#include "tokens.h"
#include "tokens-misc.h"
#include "ecdsa.h"
#include "hmac.h"
#include "emp-sh2pc/emp-sh2pc.h"

#define MERCH ALICE
#define CUST BOB

using namespace emp;

// TODO: add fail bit and count up all the validations
void issue_tokens(EcdsaPartialSig sig1, 
  bool close_tx_escrow[1024],
  EcdsaPartialSig sig2, 
  bool close_tx_merch[1024]
  ) {
  // check old pay token
  // Bit b = verify_token_sig(commitment, opening, old_state, oldpaytoken);

  // HMACKey key = commitment.key;

  // make sure wallets are well-formed
  compare_wallets();
  
  // todo: remove this
  // make sure customer committed to this new wallet
  open_commitment();

  // make sure new close transactions are well-formed
  validate_transactions();

  // sign new close transactions 
  Integer signed_merch_tx = ecdsa_sign(close_tx_escrow, sig1);
  //Integer signed_escrow_tx = ecdsa_sign(close_tx_merch, sig2);

  // sign new pay token
  // PayToken newpaytoken = sign_token(state, key);

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
  bool amount[64],
  bool *com_new,
  RevLock rl_old,
  int port,
  string ip_addr,

  State w_new,
  State w_old,
  bool *t,
  bool pt_old[256],
  bool close_tx_escrow[1024],
  bool close_tx_merch[1024],

  bool ct_masked[256],
  bool pt_masked[256]
) {
  
  // todo: replace new/delete with sweet auto
  NetIO * io = new NetIO("127.0.0.1", port);
  setup_semi_honest(io, CUST);

  EcdsaPartialSig dummy_sig;

  for (int i=0; i < 10; i+=2) {
    close_tx_escrow[1023-i] = true;
  }

  issue_tokens(dummy_sig, close_tx_escrow, dummy_sig, close_tx_merch);

  delete io;
}

void build_masked_tokens_merch(
  PubKey pkM,
  bool amount[64],
  bool *com_new,
  RevLock rl_old,
  int port,
  string ip_addr,

  bool close_mask[256],
  bool pay_mask[256],
  EcdsaPartialSig sig1,
  EcdsaPartialSig sig2,
  EcdsaPartialSig sig3
) {

  // todo: replace new/delete with sweet auto
  NetIO * io = new NetIO(nullptr, port);
  setup_semi_honest(io, MERCH);

  // hardcod test values
  for (int i=0; i < 256; i++) {
    sig1.r[i] = false;
    sig1.k_inv[i] = false;

    sig2.r[i] = false;
    sig2.k_inv[i] = false;
  }
  sig1.r[255] = true;
  sig1.r[252] = true;
  sig1.r[251] = true;

  sig1.k_inv[255] = true;

  sig2.r[245] = true;
  sig2.k_inv[255] = true; 

  // define dummy (customer) inputs
  bool dummy_tx[1024];

  issue_tokens(sig1, dummy_tx, sig2, dummy_tx);

  delete io;
}


Integer makeInteger(bool *bits, int len, int intlen, int party) {
  string bitstr = "";
  for( int i=0; i < len; i++) {
    bitstr += bits[i] ? "1" : "0";
  }
  bitstr = change_base(bitstr,2,10);
  return Integer(intlen, bitstr, party);
}

PrivateEcdsaPartialSig setEcdsaPartialSig(EcdsaPartialSig pub) { 
  PrivateEcdsaPartialSig priv;
  // probably should abstract this int initialization away
  priv.r = makeInteger(pub.r, 256, 257, MERCH);
  priv.k_inv = makeInteger(pub.k_inv, 256, 513, MERCH);
  return priv;

  string r_bitstr = "";
  string k_bitstr = "";
  for (int i=0; i < 256; i++) {
    r_bitstr += pub.r[i] ? "1" : "0";
    k_bitstr += pub.k_inv[i] ? "1" : "0";
  }
  r_bitstr = change_base(r_bitstr,2,10); // assume r is positive, not in 2's complement notation
  priv.r = Integer(257, r_bitstr, MERCH);

  k_bitstr = change_base(k_bitstr,2,10); // assume k is positive, not in 2's complement notation
  priv.k_inv = Integer(513, k_bitstr, MERCH);

  return priv;
}

PayToken sign_token(State state, HMACKey key) {
  PayToken paytoken;
  // HMACsign(key, state, paytoken);
  return paytoken;
}

Bit verify_token_sig(HMACKeyCommitment commitment, HMACKeyCommitmnetOpening opening, State oldState, PayToken paytoken) {

  // // check that the opening is valid 
  // int message[2][16];

  // for(int i=0; i<16; i++) {
  //   message[0][i] = opening.key.key[i];
  // }

  // // Padding
  // message[1][0] = 0x80000000;
  // message[1][1] = 0x00000000;
  // message[1][2] = 0x00000000;
  // message[1][3] = 0x00000000;
  // message[1][4] = 0x00000000;
  // message[1][5] = 0x00000000;
  // message[1][6] = 0x00000000;
  // message[1][7] = 0x00000000;
  // message[1][8] = 0x00000000;
  // message[1][9] = 0x00000000;
  // message[1][10] = 0x00000000;
  // message[1][11] = 0x00000000;
  // message[1][12] = 0x00000000;
  // message[1][13] = 0x00000000;

  // // Message length
  // message[1][14] = 0x00000000;
  // message[1][15] = 0x00000200;

  // Integer hashresult[8];

  // computeSHA256(message, hashresult);

  Bit b; // TODO initialize to 0

  // for(int i=0; i<8; i++) {
  //   if(commitment.commitment[i] != hashresult[i]) {
  //     b = 1;
  //   }
  // }

  // // Sign the old state again to compare
  // PayToken recomputed_paytoken;
  // HMACsign(opening.key.key, oldState, recomputed_paytoken);

  // for(int i=0; i<8; i++) {
  //   if(recomputed_paytoken.paytoken[i] != paytoken.paytoken[i]) {
  //     b = 1;
  //   }
  // }
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
