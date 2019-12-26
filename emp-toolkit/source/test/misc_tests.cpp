/*
 *
 *
 */
#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
#include "build_tokens/tokens-misc.h"
#include "build_tokens/hmac.h"
#include "build_tokens/sha256.h"
using namespace emp;
using namespace std;

// crypto++ headers
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/hmac.h"
#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"
#include "cryptopp/secblock.h"
#define byte unsigned char

// boost header to compare strings
#include <boost/algorithm/string.hpp>

void run_secure_bitcoin();
string test_output(Integer result[8]);

void validate_transactions_local(State_d new_state_d, 
  BitcoinPublicKey_d cust_escrow_pub_key_d, BitcoinPublicKey_d cust_payout_pub_key_d,
  BitcoinPublicKey_d merch_escrow_pub_key_d, BitcoinPublicKey_d merch_dispute_key_d, BitcoinPublicKey_d merch_payout_pub_key_d, 
  PublicKeyHash_d merch_publickey_hash_d, Integer escrow_digest[8], Integer merch_digest[8]);


void check_endian_swap();

void check_balance_sum();

Integer compose_buffer(Integer buffer[16]) {
  Integer thirtytwo(512, 32, PUBLIC);
  buffer[0].resize(512, false);
  Integer to_return = buffer[0];
  for(int i=1; i<16; i++) {
    buffer[i].resize(512, false);
    to_return = (to_return << thirtytwo) | buffer[i];
  }
  return to_return;
}

Integer compose_balance(Integer buffer[2]) {
  Integer thirtytwo(512, 32, PUBLIC);
  buffer[0].resize(512, false);
  Integer to_return = buffer[0];
  for(int i=1; i<2; i++) {
    buffer[i].resize(512, false);
    to_return = (to_return << thirtytwo) | buffer[i];
  }
  return to_return;
}

// The msgs we are signing are 116 bytes long, or 29 ints long
void test_end_to_end() {

  check_endian_swap();
  check_balance_sum();
  // run_secure_bitcoin();

}


// test hmac implementation 
void run_secure_bitcoin() {

  string rl_s = "f8345a21a55dc665b65c8dcfb49488b8e4f337d5c9bb843603f7222a892ce941";
  string balance_cust_s = "00e1f50500000000";
  string balance_merch_s = "00e1f50500000000";
  string txid_escrow_s = "e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4";
  string hashouts_escrow_s = "7d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d738";
  string txid_merch_s = "e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4";
  string hashouts_merch_s = "7d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d738";


  string merch_escrow_pub_key_s = "0342da23a1de903cd7a141a99b5e8051abfcd4d2d1b3c2112bac5c8997d9f12a00000000";
  string cust_escrow_pub_key_s  = "03fc43b44cd953c7b92726ebefe482a272538c7e40fdcde5994a62841525afa8d7000000";
  string merch_dispute_key_s    = "0253be79afe84fd9342c1f52024379b6da6299ea98844aee23838e8e678a765f7c000000";
  string merch_pubkey_hash_s    = "43e9e81bc632ad9cad48fc23f800021c5769a063"; //"d4354803d10e77eccfc3bf06c152ae694d05d381";
  string cust_payout_pub_key_s  = "03195e272df2310ded35f9958fd0c2847bf73b5b429a716c005d465009bd768641000000";

  string merch_payout_pub_key_s = "02f3d17ca1ac6dcf42b0297a71abb87f79dfa2c66278cbb99c1437e6570643ce90000000";

  // State_l new_state_l {
  //   struct Nonce_l nonce; // doesnt matter
  //   struct RevLock_l rl; = f8345a21a55dc665b65c8dcfb49488b8e4f337d5c9bb843603f7222a892ce941
  //   int64_t balance_cust; = 00e1f05000000000 // FOR NOW!  NEED TO FLIP ENDIANNESS LATER.  THIS IS PROPER LITTLE ENDIAN
  //   int64_t balance_merch; = 00e1f05000000000
  //   struct Txid_l txid_merch; = doesnt matter
  //   struct Txid_l txid_escrow; = e162d4625d3a6bc72f2c938b1e29068a00f42796aacc323896c235971416dff4
  //   struct Txid_l HashPrevOuts_merch; = doesnt matter
  //   struct Txid_l HashPrevOuts_escrow = 7d03c85ecc9a0046e13c0dcc05c3fb047762275cb921ca150b6f6b616bd3d738;
  // }

  string temp;

  struct State_l state_l;

  struct BitcoinPublicKey_l merch_escrow_pub_key_l;
  struct BitcoinPublicKey_l merch_dispute_key_l;
  struct BitcoinPublicKey_l merch_payout_pub_key_l; // TODO SET THIS AS AN INPUT
  struct BitcoinPublicKey_l cust_escrow_pub_key_l;
  struct BitcoinPublicKey_l cust_payout_pub_key_l;

  struct PublicKeyHash_l merch_pubkey_hash_l;

  for(int i=0; i<8; i++) {
    temp = rl_s.substr(i*8, 8);
    state_l.rl.revlock[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<2; i++) {
    temp = balance_cust_s.substr(i*8, 8);
    state_l.balance_cust.balance[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

    for(int i=0; i<2; i++) {
    temp = balance_merch_s.substr(i*8, 8);
    state_l.balance_merch.balance[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<8; i++) {
    temp = txid_escrow_s.substr(i*8, 8);
    state_l.txid_escrow.txid[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<8; i++) {
    temp = hashouts_escrow_s.substr(i*8, 8);
    state_l.HashPrevOuts_escrow.txid[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<8; i++) {
    temp = txid_merch_s.substr(i*8, 8);
    state_l.txid_merch.txid[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<8; i++) {
    temp = hashouts_merch_s.substr(i*8, 8);
    state_l.HashPrevOuts_merch.txid[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<9; i++) {
    temp = merch_escrow_pub_key_s.substr(i*8, 8);
    merch_escrow_pub_key_l.key[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<9; i++) {
    temp = merch_dispute_key_s.substr(i*8, 8);
    merch_dispute_key_l.key[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<9; i++) {
    temp = merch_payout_pub_key_s.substr(i*8, 8);
    merch_payout_pub_key_l.key[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<9; i++) {
    temp = cust_escrow_pub_key_s.substr(i*8, 8);
    cust_escrow_pub_key_l.key[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<9; i++) {
    temp = cust_payout_pub_key_s.substr(i*8, 8);
    cust_payout_pub_key_l.key[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<5; i++) {
    temp = merch_pubkey_hash_s.substr(i*8, 8);
    merch_pubkey_hash_l.hash[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }


  State_d state_d = distribute_State(state_l, CUST);
  BitcoinPublicKey_d merch_escrow_pub_key_d = distribute_BitcoinPublicKey(merch_escrow_pub_key_l, PUBLIC);
  BitcoinPublicKey_d merch_dispute_key_d = distribute_BitcoinPublicKey(merch_dispute_key_l, PUBLIC);
  BitcoinPublicKey_d merch_payout_pub_key_d = distribute_BitcoinPublicKey(merch_payout_pub_key_l, PUBLIC);
  BitcoinPublicKey_d cust_escrow_pub_key_d = distribute_BitcoinPublicKey(cust_escrow_pub_key_l, CUST);
  BitcoinPublicKey_d cust_payout_pub_key_d = distribute_BitcoinPublicKey(cust_payout_pub_key_l, CUST);
  PublicKeyHash_d merch_pubkey_hash_d = distribute_PublicKeyHash(merch_pubkey_hash_l, PUBLIC);

}


void check_endian_swap() {
  string balance_swap_string = "0102030405060708";

  string temp;

  Balance_l balance_swap_l;
  for(int i=0; i<2; i++) {
    temp = balance_swap_string.substr(i*8, 8);
    balance_swap_l.balance[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);    
  }

  Balance_d balance_swap_d = distribute_Balance(balance_swap_l, PUBLIC);

  Balance_d swaped_balance_d = convert_to_little_endian(balance_swap_d);

  Balance_d swaped_back_balance_d = convert_to_big_endian(swaped_balance_d);

  Integer swaped_balance_int_d = compose_balance(swaped_balance_d.balance);

  string swaped_balance_s = swaped_balance_int_d.reveal_unsigned(PUBLIC,16);
  while (swaped_balance_s.length() < 16) {
    swaped_balance_s = '0' + swaped_balance_s;
  }

  Integer swaped_back_balance_int_d = compose_balance(swaped_back_balance_d.balance);

  string swaped_back_balance_s = swaped_back_balance_int_d.reveal_unsigned(PUBLIC,16);
  while (swaped_back_balance_s.length() < 16) {
    swaped_back_balance_s = '0' + swaped_back_balance_s;
  }

  assert ( swaped_balance_s.compare("0807060504030201") == 0 );
  assert ( swaped_back_balance_s.compare("0102030405060708") == 0 );

  cout << "Passed Endian Swap Tests";
}

void check_balance_sum() {

  string balance_zero_string = "1111111111111111";
  string balance_one_string =  "12345678fabcde01";

  string temp;

  Balance_l balance_zero_l;
  for(int i=0; i<2; i++) {
    temp = balance_zero_string.substr(i*8, 8);
    balance_zero_l.balance[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);    
  }

  Balance_l balance_one_l;
  for(int i=0; i<2; i++) {
    temp = balance_one_string.substr(i*8, 8);
    balance_one_l.balance[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);    
  }

  Balance_d balance_zero_d = distribute_Balance(balance_zero_l, PUBLIC);
  Balance_d balance_one_d  = distribute_Balance(balance_one_l, PUBLIC);

  Balance_d sum_d = sum_balances(balance_zero_d, balance_one_d);

  Integer sum_int_d = compose_balance(sum_d.balance);

  string sum_int_s = sum_int_d.reveal_unsigned(PUBLIC,16);
  while (sum_int_s.length() < 16) {
    sum_int_s = '0' + sum_int_s;
  }

  assert ( sum_int_s.compare("2345678a0bcdef12") == 0 );

  cout << "Passed Sum Test";

}

int main(int argc, char** argv) {
  // run in semihonest library
  int port, party;
  if (argc != 3) {
    cerr << "ERROR: not enough args" << endl;
    return 1;
  }
  parse_party_and_port(argv, &party, &port);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  // run end-to-end tests
  test_end_to_end();

  delete io;
  return 0;
}