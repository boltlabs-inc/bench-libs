#include "tokens.h"
#include "tokens-misc.h"
#include "ecdsa.h"
#include "hmac.h"
#include "sha256.h"
#include "emp-sh2pc/emp-sh2pc.h"

#define MERCH ALICE
#define CUST BOB

using namespace emp;

// TODO: add fail bit and count up all the validations
void issue_tokens(
/* CUSTOMER INPUTS */
  State_l old_state_l,
  State_l new_state_l,
  PayToken_l old_paytoken_l,
  BitcoinPublicKey_l cust_escrow_pub_key_l,
  BitcoinPublicKey_l cust_payout_pub_key_l,
/* MERCHANT INPUTS */
  HMACKey_l hmac_key_l,
  Mask_l paytoken_mask_l,
  Mask_l merch_mask_l,
  Mask_l escrow_mask_l,
  /* TODO: ECDSA Key info */
/* PUBLIC INPUTS */
  Balance_l epsilon_l,
  HMACKeyCommitment_l hmac_key_commitment_l,
  MaskCommitment_l paytoken_mask_commitment_l,
  RevLockCommitment_l rlc_l,
  Nonce_l nonce_l,
  BitcoinPublicKey_l merch_escrow_pub_key_l,
  BitcoinPublicKey_l merch_dispute_key_l, 
  PublicKeyHash_l merch_publickey_hash_l,
/* OUTPUTS */
  EcdsaPartialSig_l sig1, 
  char close_tx_escrow[1024],
  EcdsaPartialSig_l sig2, 
  char close_tx_merch[1024]
  ) {

  State_d old_state_d = distribute_State(old_state_l, CUST);
  State_d new_state_d = distribute_State(new_state_l, CUST);
  PayToken_d old_paytoken_d = distribute_PayToken(old_paytoken_l, CUST);
  BitcoinPublicKey_d cust_escrow_pub_key_d = distribute_BitcoinPublicKey(cust_escrow_pub_key_l, CUST);
  BitcoinPublicKey_d cust_payout_pub_key_d = distribute_BitcoinPublicKey(cust_payout_pub_key_l, CUST);

  HMACKey_d hmac_key_d = distribute_HMACKey(hmac_key_l, MERCH);
  Mask_d paytoken_mask_d = distribute_Mask(paytoken_mask_l, MERCH);
  Mask_d merch_mask_d = distribute_Mask(merch_mask_l, MERCH);
  Mask_d escrow_mask_d = distribute_Mask(escrow_mask_l, MERCH);

  Balance_d epsilon_d = distribute_Balance(epsilon_l, PUBLIC); // IVE BEEN TREATING THIS LIKE A 32 BIT VALUE, BUT ITS 64
  HMACKeyCommitment_d hmac_key_commitment_d = distribute_HMACKeyCommitment(hmac_key_commitment_l, PUBLIC);
  MaskCommitment_d paytoken_mask_commitment_d = distribute_MaskCommitment(paytoken_mask_commitment_l, PUBLIC);
  RevLockCommitment_d rlc_d = distribute_RevLockCommitment(rlc_l, PUBLIC);
  Nonce_d nonce_d = distribute_Nonce(nonce_l, PUBLIC);
  BitcoinPublicKey_d merch_escrow_pub_key_d = distribute_BitcoinPublicKey(merch_escrow_pub_key_l, PUBLIC);
  BitcoinPublicKey_d merch_dispute_key_d = distribute_BitcoinPublicKey(merch_dispute_key_l, PUBLIC);
  PublicKeyHash_d merch_publickey_hash_d = distribute_PublicKeyHash(merch_publickey_hash_l, PUBLIC);


  // check old pay token
  Bit b = verify_token_sig(hmac_key_commitment_d, hmac_key_d, old_state_d, old_paytoken_d);

  // make sure wallets are well-formed
  b = (b | compare_wallets(old_state_d, new_state_d, rlc_d, nonce_d, epsilon_d));
  
  // todo: remove this
  // make sure customer committed to this new wallet
  Integer escrow_digest[8];

  // make sure new close transactions are well-formed
  validate_transactions(new_state_d, 
    cust_escrow_pub_key_d, cust_payout_pub_key_d,
    merch_escrow_pub_key_d, merch_dispute_key_d, merch_publickey_hash_d,
    escrow_digest);

  // we should return into these txserialized_d or hash 

  // sign new close transactions 
  Integer signed_merch_tx = ecdsa_sign(close_tx_escrow, sig1);
  //Integer signed_escrow_tx = ecdsa_sign(close_tx_merch, sig2);

  // sign new pay token
  PayToken_d new_paytoken_d = sign_token(new_state_d, hmac_key_d);

  // Transform the signed_merch_tx into the correct format --> array of 8 32bit uints
  Integer signed_merch_tx_parsed[8];
  Integer signed_escrow_tx_parsed[8];

  // mask pay and close tokens
  b = ( b | mask_paytoken(new_paytoken_d.paytoken, paytoken_mask_d, paytoken_mask_commitment_d)); // pay token 

  mask_closemerchtoken(signed_merch_tx_parsed, merch_mask_d); // close token - merchant close 
  mask_closeescrowtoken(signed_escrow_tx_parsed, escrow_mask_d); // close token - escrow close 

  // ...return masked tokens
  // If b = 1, we need to return nothing of value.  Otherwise we need to return all 1's or something.
  //   we can do this by or-ing b into everything!
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
  struct PubKey pkM,
  uint64_t amount,
  struct RevLock_l rl_com, // TYPISSUE: this doesn't match the docs. should be a commitment
  int port,
  char ip_addr[15],
  struct MaskCommitment_l paymask_com,
  struct HMACKeyCommitment_l key_com,

  struct State_l w_new,
  struct State_l w_old,
  char *t,
  struct PayToken_l pt_old,
  char close_tx_escrow[1024],
  char close_tx_merch[1024],

  char ct_masked[256],
  char pt_masked[256]
) {
  // todo: replace new/delete with sweet auto
  NetIO * io = new NetIO("127.0.0.1", port);
  setup_semi_honest(io, CUST);

  // hardcoded data for run-throughs 
  for (int i=0; i<1024; i++) {
    close_tx_escrow[i] = '1';
  }
  for (int i=0; i < 10; i+=2) {
    close_tx_escrow[1023-i] = '0';
  }

  // placeholders for vars passed by merchant
  // TODO maybe do all the distributing here, before calling issue_tokens
  HMACKey_l hmac_key_l;
  Mask_l paytoken_mask_l;
  MaskCommitment_l paytoken_mask_commitment_l;
  RevLockCommitment_l rlc_l;
  Mask_l merch_mask_l;
  Mask_l escrow_mask_l;
  EcdsaPartialSig_l dummy_sig;
  BitcoinPublicKey_l cust_escrow_pub_key_l;
  BitcoinPublicKey_l merch_escrow_pub_key_l;
  Nonce_l nonce_l;
  BitcoinPublicKey_l merch_dispute_key_l;
  PublicKeyHash_l merch_publickey_hash;
  Balance_l epsilon_l;
  BitcoinPublicKey_l cust_payout_pub_key_l;

issue_tokens(
/* CUSTOMER INPUTS */
  w_old,
  w_new,
  pt_old,
  cust_escrow_pub_key_l,
  cust_payout_pub_key_l,
/* MERCHANT INPUTS */
  hmac_key_l,
  paytoken_mask_l,
  merch_mask_l,
  escrow_mask_l,
  /* TODO: ECDSA Key info */
/* PUBLIC INPUTS */
  epsilon_l,
  key_com,
  paytoken_mask_commitment_l,
  rlc_l,
  nonce_l,
  merch_escrow_pub_key_l,
  merch_dispute_key_l, 
  merch_publickey_hash,
/* OUTPUTS */
  dummy_sig,
  close_tx_escrow,
  dummy_sig,
  close_tx_merch
  );

  delete io;
}

void build_masked_tokens_merch(
  struct PubKey pkM,
  uint64_t amount,
  struct RevLock_l rl_com, // TYPISSUE: this doesn't match the docs. should be a commitment
  int port,
  char ip_addr[15],
  struct MaskCommitment_l paymask_com,
  struct HMACKeyCommitment_l key_com,

  struct HMACKey_l hmac_key,
  struct Mask_l close_mask,
  struct Mask_l pay_mask,
  struct EcdsaPartialSig_l sig1,
  struct EcdsaPartialSig_l sig2,
  struct EcdsaPartialSig_l sig3
) {

  // todo: replace new/delete with sweet auto
  NetIO * io = new NetIO(nullptr, port);
  setup_semi_honest(io, MERCH);

  // hardcode test values using boost to get char*s.

  string r = "108792476108599305057612221643697785065475034835954270988586688301027220077907";
  string k_inv = "44657876998057202178264530375095959644163723589174927475562391733096641768603";

  fillEcdsaPartialSig_l(&sig1, r, k_inv);
  fillEcdsaPartialSig_l(&sig2, r, k_inv);

  // define dummy (customer) inputs
  char dummy_tx[1024];
  // fill this in so signature_hash doesn't crash 
  // TODO find a better way/location to initialize vars
  for (int i=0; i<1024; i++) {
    dummy_tx[i] = '0';  
  }

  State_l old_state_l;
  State_l new_state_l;
  PayToken_l old_paytoken_l;
  Mask_l paytoken_mask_l;
  MaskCommitment_l paytoken_mask_commitment_l;
  RevLockCommitment_l rlc_l;
  Mask_l merch_mask_l;
  Mask_l escrow_mask_l;
  BitcoinPublicKey_l cust_escrow_pub_key_l;
  BitcoinPublicKey_l merch_escrow_pub_key_l;
  Nonce_l nonce_l;
  BitcoinPublicKey_l merch_dispute_key_l;
  PublicKeyHash_l merch_publickey_hash;
  Balance_l epsilon_l;
  BitcoinPublicKey_l cust_payout_pub_key_l;

issue_tokens(
/* CUSTOMER INPUTS */
  old_state_l,
  new_state_l,
  old_paytoken_l,
  cust_escrow_pub_key_l,
  cust_payout_pub_key_l,
/* MERCHANT INPUTS */
  hmac_key,
  paytoken_mask_l,
  merch_mask_l,
  escrow_mask_l,
  /* TODO: ECDSA Key info */
/* PUBLIC INPUTS */
  epsilon_l,
  key_com,
  paytoken_mask_commitment_l,
  rlc_l,
  nonce_l,
  merch_escrow_pub_key_l,
  merch_dispute_key_l, 
  merch_publickey_hash,
/* OUTPUTS */
  sig1,
  dummy_tx,
  sig2,
  dummy_tx
  );

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

/*
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
*/

PayToken_d sign_token(State_d state, HMACKey_d key) {
  PayToken_d paytoken;
  HMACsign(key, state, paytoken.paytoken);
  return paytoken;
}

Bit verify_token_sig(HMACKeyCommitment_d commitment, HMACKey_d opening, State_d old_state, PayToken_d old_paytoken) {

  // check that the opening is valid 
  Integer message[2][16];

  for(int i=0; i<16; i++) {
    message[0][i] = opening.key[i];
  }

  // Padding
  message[1][0] = Integer(32, -2147483648, PUBLIC); //0x80000000;
  message[1][1] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][2] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][3] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][4] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][5] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][6] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][7] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][8] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][9] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][10] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][11] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][12] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][13] = Integer(32, 0, PUBLIC); //0x00000000;

  // Message length 
  message[1][14] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][15] = Integer(32, 512, PUBLIC);

  Integer hashresult[8];

  computeSHA256_2d(message, hashresult);

  Bit b; // TODO initialize to 0

  for(int i=0; i<8; i++) {
     Bit not_equal = !(commitment.commitment[i].equal(hashresult[i]));
     b = b | not_equal;
  }

  // // Sign the old state again to compare
  PayToken_d recomputed_paytoken;
  HMACsign(opening, old_state, recomputed_paytoken.paytoken);

  for(int i=0; i<8; i++) {
    Bit not_equal = !(recomputed_paytoken.paytoken[i].equal(old_paytoken.paytoken[i]));
    b = b | not_equal;
  }
  return b;
}

// make sure wallets are well-formed
Bit compare_wallets(State_d old_state_d, State_d new_state_d, RevLockCommitment_d rlc_d, Nonce_d nonce_d, Balance_d epsilon_d) {

  //Make sure the fields are all correct
  Bit b; // TODO initialize to 0

  for(int i=0; i<8; i++) {
     Bit not_equal = !(old_state_d.txid_merch.txid[i].equal(new_state_d.txid_merch.txid[i]));
     b = b | not_equal;
  }

  for(int i=0; i<8; i++) {
     Bit not_equal = !(old_state_d.txid_escrow.txid[i].equal(new_state_d.txid_escrow.txid[i]));
     b = b | not_equal;
  }

  // Transform balances into Integer64_t
  // Integer epsilon_d_local = 
  // TODO THIS IS VERY VERY BROKEN!!!
  // Need to know how to compare and do math on balances
  b = (b | (!new_state_d.balance_merch.balance[0].equal(old_state_d.balance_merch.balance[0] + epsilon_d.balance[0])));
  b = (b | (!new_state_d.balance_cust.balance[0].equal(old_state_d.balance_cust.balance[0] - epsilon_d.balance[0])));


  // ZERO CHECK
  // Make sure both Custom and Merch are going to be nonzero balances after epsilon
  Integer zero(32, 0, PUBLIC);

  b = (b | (!new_state_d.balance_merch.balance[0].geq(zero)));
  b = (b | (!new_state_d.balance_cust.balance[0].geq(zero)));

  // nonce_d has to match the nonce in old state

  b = (b | (!old_state_d.nonce.nonce[0].equal(nonce_d.nonce[0])));
  b = (b | (!old_state_d.nonce.nonce[1].equal(nonce_d.nonce[1])));
  b = (b | (!old_state_d.nonce.nonce[2].equal(nonce_d.nonce[2])));
  b = (b | (!old_state_d.nonce.nonce[3].equal(nonce_d.nonce[3])));

  // check that the rlc is a commitment to the rl in old_state

  b = (b | verify_revlock_commitment(old_state_d.rl, rlc_d));

  return b;
}

// make sure customer committed to this new wallet
Bit open_commitment() {
  Bit b;
  return b;
}

Bit verify_revlock_commitment(RevLock_d rl_d, RevLockCommitment_d rlc_d) {
  Bit b;  // TODO initialize to 0

  Integer message[1][16];

  for(int i=0; i<8; i++) {
    message[0][i] = rl_d.revlock[i];
  }

  message[0][8] = Integer(32, -2147483648, PUBLIC); //0x80000000;
  message[0][9] = Integer(32, 0, PUBLIC); //0x00000000;
  message[0][10] = Integer(32, 0, PUBLIC); //0x00000000;
  message[0][11] = Integer(32, 0, PUBLIC); //0x00000000;
  message[0][12] = Integer(32, 0, PUBLIC); //0x00000000;
  message[0][13] = Integer(32, 0, PUBLIC); //0x00000000;

  // Message length 
  message[0][14] = Integer(32, 0, PUBLIC); //0x00000000;
  message[0][15] = Integer(32, 256, PUBLIC);

  Integer hashresult[8];

  computeSHA256_1d(message, hashresult);

  for(int i=0; i<8; i++) {
     Bit not_equal = !(rlc_d.commitment[i].equal(hashresult[i]));
     b = b | not_equal;
  }
  return b;
}

Bit verify_mask_commitment(Mask_d mask, MaskCommitment_d maskcommitment) {
  Bit b;  // TODO initialize to 0

  Integer message[1][16];

  for(int i=0; i<8; i++) {
    message[0][i] = mask.mask[i];
  }

  message[0][8] = Integer(32, -2147483648, PUBLIC); //0x80000000;
  message[0][9] = Integer(32, 0, PUBLIC); //0x00000000;
  message[0][10] = Integer(32, 0, PUBLIC); //0x00000000;
  message[0][11] = Integer(32, 0, PUBLIC); //0x00000000;
  message[0][12] = Integer(32, 0, PUBLIC); //0x00000000;
  message[0][13] = Integer(32, 0, PUBLIC); //0x00000000;

  // Message length 
  message[0][14] = Integer(32, 0, PUBLIC); //0x00000000;
  message[0][15] = Integer(32, 256, PUBLIC);

  Integer hashresult[8];

  computeSHA256_1d(message, hashresult);

  for(int i=0; i<8; i++) {
     Bit not_equal = !(maskcommitment.commitment[i].equal(hashresult[i]));
     b = b | not_equal;
  }
  return b;
}

// make sure new close transactions are well-formed
void validate_transactions(State_d new_state_d, 
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, PublicKeyHash_d merch_publickey_hash_d,
  Integer escrow_digest[8])
{


}

// mask pay and close tokens
Bit mask_paytoken(Integer paytoken[8], Mask_d mask, MaskCommitment_d maskcommitment) {

  // The pay token is 256 bits long.
  // Thus the mask is 256 bits long.
  // First we check to see if the mask was correct

  Bit b = verify_mask_commitment(mask, maskcommitment);

  for(int i=0; i<8; i++) {
    paytoken[i] = paytoken[i] ^ mask.mask[i];
  }

  return b;
}

void mask_closemerchtoken(Integer token[8], Mask_d mask) {

  // The sig is 256 bits long.
  // Thus the mask is 256 bits long.

  for(int i=0; i<8; i++) {
    token[i] = token[i] ^ mask.mask[i];
  }

}

void mask_closeescrowtoken(Integer token[8], Mask_d mask){

  // The sig is 256 bits long.
  // Thus the mask is 256 bits long.

  for(int i=0; i<8; i++) {
    token[i] = token[i] ^ mask.mask[i];
  }
}
