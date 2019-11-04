/*
 * describes an API for calling EMP-toolkit (and other??) MPC functions
 *
 * to be integrated into Rust implementation
 */

/* public and private key pair types */

/* \param pubkey    : a public key. probably not an integer */
struct PubKey{
  int pubkey;
};
/* \param privkey    : a private key. probably not an integer */
struct PrivKey {
  int privkey;
};

/* wallet type
 *
 * \param pkC           : customer public key 
 * \param wpk           : wallet public key (maybe not the same pubkey type?)
 * \param balance_cust  : customer balance
 * \param balance_merch : merchant balance
 * \param txid_merch    : transaction ID for merchant close transaction (bits, formatted as they appear in the 'source' field of a transaction that spends it)
 * \param txid_escrow   : transaction ID for escrow transaction (ditto on format)
 */
struct Wallet {
  PubKey pkC;
  PubKey wpk;
  int balance_cust;
  int balance_merch;
  bool *txid_merch;
  bool *txid_escrow;
};

/* Commitment type
 * \param params    : parameters for the commitment scheme (not an int)
 * \param com       : commitment value
 */
struct Commit {
  int params;
  int com;
};


/* customer's token generation function
 *
 * runs MPC to compute masked tokens (close- and pay-).
 * blocks until computation is finished.
 *
 * option: port could be fixed in advance (not passed in here)
 * 
 * \param[in] pkM       : (shared) merchant public key
 * \param[in] amount    : (shared) transaction amount 
 * \param[in] com_new   : (shared) commitment to new wallet object
 * \param[in] wpk_old   : (shared) previous wallet public key
 * \param[in] port      : (shared) communication port
 * \param[in] ip_addr   : (shared) merchant's IP address
 *
 * \param[in] w_new     : (private) new wallet object
 * \param[in] w_old     : (private) previous wallet object
 * \param[in] t_new     : (private) commitment randomness
 * \param[in] pt_old    : (private) previous pay token (not an int)
 * \param[in] close_tx_escrow   : (private) bits of new close transaction (spends from escrow)
 * \param[in] close_tx_merch    : (private) bits of new close transaction (spends from merchant close transaction)
 * 
 * \param[out] ct_masked    : masked close token
 * \param[out] pt_masked    : masked pay token
 *
 */
void build_masked_tokens_cust(
  PubKey pkM,
  int amount,
  Commit com_new,
  PubKey wpk_old,

  Wallet w_new,
  Wallet w_old,
  int t,
  int pt_old, 
  bool *close_tx_escrow,
  bool *close_tx_merch,

  int *ct_masked,
  int *pt_masked
);


/* merchant's close-token computation function 
 *
 * Pre-computes some parameters, then runs MPC to compute masked tokens (close- and pay-)
 * blocks until computation is finished.
 *
 * Generates a partial ECDSA signature:
 *   1. Sample: k <- Z_q, k
 *   2. Compute random curve point: (r_x, r_y) = k * G
 *   3. Compute secret curve point: spt = (r_x * skM) mod q
 *   4. Compute inverse: k_inv = k^(-1)
 * Then calls MPC with shared inputs, plus k_inv, spt.
 *
 * option: port could be fixed in advance (not passed in here)
 *
 * \param[in] pkM       : (shared) merchant public key
 * \param[in] amount    : (shared) transaction amount 
 * \param[in] com_new   : (shared) commitment to new wallet object
 * \param[in] wpk_old   : (shared) previous wallet public key
 * \param[in] port      : (shared) communication port
 * \param[in] ip_addr   : (shared) customer's IP address
 *
 * \param[in] skM       : (private) merchant ECDSA secret key
 *
 * Merchant does not receive output.
 *
 */
void build_masked_tokens_merch(
  PubKey pkM,
  int amount,
  Commit com_new,
  PubKey wpk_old,

  PrivKey skM
);





