/*
 * describes an API for calling MPC functions 
 * 
 * to be integrated into Rust implementation
 *
 * This describes the basic high-level inputs we expect from the protocol.
 * There is some additional precomputation that will happen in the clear,
 * plus mangling of pretty Rust/C++ types to match the format used by
 * the MPC frameworks
 *
 * TYPISSUE - There are some weird types here, as well. Everything has a type,
 * but some of them are clearly incorrect 
 * (e.g.a public key will not fit into a normal 32-bit integer). 
 * but I don't know what representation they -will- take.
 * I've marked such parameters with TYPISSUE
 *
 * Comments are sort of in doxygen style.
 */

/* ECDSA public and private key pair types */
/* \param pubkey    : a public key. TYPISSUE - probably not an integer */
struct PubKey{
  int pubkey;
};
/* \param privkey    : a private key. TYPISSUE - probably not an integer */
struct PrivKey {
  int privkey;
};

/* wallet type
 *
 * \param pkC           : customer public key 
 * \param wpk           : wallet public key (TYPISSUE - maybe not the same as as signing key?)
 * \param balance_cust  : customer balance (TYPISSUE - do we want to allow larger transactions?)
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
 * \param params    : parameters for the commitment scheme (TYPISSUE - this will be a set of parameters including modulus q_com)
 * \param com       : commitment value (TYPISSUE - this is an int mod q_com, may be bigger than 32 bits)
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
 * \param[in] amount    : (shared) transaction amount (TYPISSUE)
 * \param[in] com_new   : (shared) commitment to new wallet object
 * \param[in] wpk_old   : (shared) previous wallet public key
 * \param[in] port      : (shared) communication port
 * \param[in] ip_addr   : (shared) merchant's IP address
 *
 * \param[in] w_new     : (private) new wallet object
 * \param[in] w_old     : (private) previous wallet object
 * \param[in] t_new     : (private) commitment randomness (TYPISSUE)
 * \param[in] pt_old    : (private) previous pay token (TYPISSUE - not an int)
 * \param[in] close_tx_escrow   : (private) bits of new close transaction (spends from escrow)
 * \param[in] close_tx_merch    : (private) bits of new close transaction (spends from merchant close transaction)
 * 
 * \param[out] ct_masked    : masked close token (TYPISSUE - definitely a pointer, maybe not an int)
 * \param[out] pt_masked    : masked pay token (TYPISSUE - definitely a pointer, maybe not an int)
 *
 */
void build_masked_tokens_cust(
  PubKey pkM,
  int amount,
  Commit com_new,
  PubKey wpk_old,
  int port,
  int ip_addr,

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
 * \param[in] amount    : (shared) transaction amount (TYPISSUE)
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
  int port,
  int ip_addr,

  PrivKey skM
);





