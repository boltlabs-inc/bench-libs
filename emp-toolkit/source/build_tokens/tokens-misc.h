#pragma once
#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;

/* TODO: Fix types for all of these */

/* issue tokens
 * parent function; implements Protocol Pi_{ IssueTokens }
 * as described in bolt.pdf
 */
void issue_tokens();

/* SIGNATURE SCHEME
 * for the pay token. We haven't decided which one to use.
 * Also haven't finalized representation for tokens.
 */
void sign_token();
Bit verify_token_sig();

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

