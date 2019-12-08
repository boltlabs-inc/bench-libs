#pragma once
#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens.h"
using namespace emp;

#define MERCH ALICE
#define CUST BOB

/*********** We give all the types in pairs. _l structures are local var and _d are distributed**************/

/* HMAC Key structure.
 * HMAC Keys are the length of the block-size of the underlying hash functions
 * SHA256 has a block size of 512 bits, so we need 16 integers to represent the whole thing
 */
struct HMACKey_l {
  uint32_t key[16]; //TODO uint8_t[64] seems better
};

struct HMACKey_d {
  Integer key[16];
};

/* Revocation lock - TYPISSUE: not sure what type this is yet.
 * Tentatively sized to use a hash (SHA256-based) commitment scheme.
 * \param rl 	: a revocation lock.
 */
struct RevLock_l {
  uint32_t revlock[8];
};

struct RevLock_d {
  Integer revlock[8];
};

/* This is a pay token
 * Is is an HMAC computed on the state 
 * The output of HMAC is the underlying block size.  In this case 256 bits
 */
struct PayToken_l {
  int paytoken[8];
};

struct PayToken_d {
  Integer paytoken[8];
};

/* This is a nonce.  Its used to prevent double spends
 * RIGHT NOW THIS THING IS 96 BITS.  WE MAY WANT TO INCREASE ITS LENGTH IN THE FUTURE!!!
 */
struct Nonce_l {
  uint32_t nonce[3];
};

struct Nonce_d {
  Integer nonce[3];
};

/* state type
 *
 * \param pkC           : customer public key 
 * \param rl 			: revocation lock for 
 * \param balance_cust  : customer balance 
 * \param balance_merch : merchant balance
 * \param txid_merch    : transaction ID for merchant close transaction (bits, formatted as they appear in the 'source' field of a transaction that spends it) 
 * \param txid_escrow   : transaction ID for escrow transaction (ditto on format)
 */
struct State_l {
  Nonce_l nonce;
  RevLock_l rl;
  int32_t balance_cust;
  int32_t balance_merch;
  uint32_t txid_merch[8];
  uint32_t txid_escrow[8];
};

struct State_d {
  Nonce_d nonce;
  RevLock_d rl;
  Integer balance_cust;
  Integer balance_merch;
  Integer txid_merch[8];
  Integer txid_escrow[8];
};

/* Partial ECDSA signature
 * This is a partial signature. It is based on a raondomly chosen k, message x, public key G, and public modulus q. Let (rx, ry) = kG.
 * \param r     : r = rx*x mod q. Represented as a decimal string. (256 bits)
 * \param k_inv : k_inv = k^-1. Represented as a decimal string. (256 bits)
 */
struct EcdsaPartialSig_l {
  string r;
  string k_inv;
};

struct EcdsaPartialSig_d {
  Integer r;
  Integer k_inv;
};


/********************* Casting functions  **********************/

HMACKey_d distribute_HMACKey(HMACKey_l key);
HMACKey_l localize_HMACKey(HMACKey_d key);

RevLock_d distribute_RevLock(RevLock_l revlock);
RevLock_l localize_RevLock(RevLock_d revlock);

PayToken_d distribute_PayToken(PayToken_l paytoken);
PayToken_l localize_PayToken(PayToken_d paytoken);

Nonce_d distribute_Nonce(Nonce_l nonce);
Nonce_l localize_Nonce(Nonce_d nonce);

State_d distribute_State(State_l state);
State_l localize_State(State_d state);

EcdsaPartialSig_d distribute_EcdsaPartialSig(EcdsaPartialSig_l ecdsapartialsig);
EcdsaPartialSig_l localize_EcdsaPartialSig(EcdsaPartialSig_d ecdsapartialsig);

// void distribute_HMACKey(HMACKey_d destination, HMACKey_l source);
// void localize_HMACKey(HMACKey_l destination, HMACKey_d source);

// void distribute_RevLock(RevLock_d destination, RevLock_l source);
// void localize_RevLock(RevLock_l destination, RevLock_d source);

// void distribute_PayToken(PayToken_d destination, PayToken_l source);
// void localize_PayToken(PayToken_l destination, PayToken_d source);

// void distribute_State(State_d destination, State_l source);
// void localize_State(State_l destination, State_d source);

// void distribute_EcdsaPartialSig(EcdsaPartialSig_d destination, EcdsaPartialSig_l source);
// void localize_EcdsaPartialSig(EcdsaPartialSig_l destination, EcdsaPartialSig_d ecdsapartialsig);

/***************************** THIS FROM MARCELLA BEFORE THE GREAT RE-TYPING ************************/

/* Private partial ECDSA signature
 * \param r     : A value for a partial ecdsa signature, k randomly chosen: (rx, ry) = kG, and r = rx*x mod q
 * \param k_inv : For the randomly chosen k, k_inv = k^-1
 */
/*
   struct PrivateEcdsaPartialSig {
   Integer r;
   Integer k_inv;
   };

   PrivateEcdsaPartialSig setEcdsaPartialSig(EcdsaPartialSig pub ); 
   */

Integer makeInteger(bool *bits, int len, int intlen, int party);

/* TODO: Fix types for all of these */

/* issue tokens
 * parent function; implements Protocol Pi_{ IssueTokens }
 * as described in bolt.pdf
 */
void issue_tokens(struct EcdsaPartialSig_l sig1, 
    bool close_tx_escrow[1024],
    struct EcdsaPartialSig_l sig2, 
    bool close_tx_merch[1024]
    );

/* SIGNATURE SCHEME
 * for the pay token. We haven't decided which one to use.
 * Also haven't finalized representation for tokens.
 */
// void sign_token();
struct PayToken sign_token(struct State state, struct HMACKey key);
// Bit verify_token_sig();
Bit verify_token_sig(
  struct HMACKeyCommitment commitment, 
  struct HMACKeyCommitmnetOpening opening, 
  struct State oldState, 
  struct PayToken paytoken);


/* checks that the wallets are appropriately updated
 * 0. old wallet ID matches publicly revealed wkpi
 * 1. wallet customer keys match
 * 2. escrow transactions match
 * 3. merchant-close transactions match
 * 4. balances are correctly updated by amt
 *  
 * \param[in] w_old 	: old wallet
 * \param[in] w_new 	: new wallet
 * \param[in] amt 		: transaction amount
 * \param[in] wpk_old 	: old wallet ID
 *
 * \return b 	: success bit
 */
Bit compare_wallets();

/* opens and verifies commitment to a wallet
 * e.g. checks that com == commit(w;t)
 * where commit is a SHA256 commitment scheme
 * 
 * \param[in] com   : commitment to new wallet object using a SHA256 commitment
 * \param[in] w     : wallet object
 * \param[in] t     : commitment randomness (TYPISSUE)
 *
 * \return b 	: success bit
 */
Bit open_commitment();

/* validates closing transactions against a wallet
 * for each transaction:
 * 0. check that balances are correct
 * 1. check that wallet key is integrated correctly
 * 2. check that source is correct
 *    for close_tx_merch, source is txid_merch
 *    for close_tx_escrow, source is txid_escrow
 * 
 * \param[in] w     			: wallet object
 * \param[in] close_tx_escrow   : (private) bits of new close transaction (spends from escrow). no more than 1024 bits.
 * \param[in] close_tx_merch    : (private) bits of new close transaction (spends from merchant close transaction). No more than 1024 bits.
 *
 * \return b 	: success bit
 */
Bit validate_transactions();

/* applies a mask to a token
 * uses a one-time-pad scheme (just xors mask with token bits)
 *
 * updates the token in-line
 *
 * \param[in] mask 	: A random mask 
 * \param[in] token : Sequence of bits representing a token
 *
 */
void mask_token();

