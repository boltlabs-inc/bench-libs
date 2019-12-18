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

string reference_HMAC_sign(CryptoPP::SecByteBlock key, string msg);
string run_secure_HMACsign(string key, string msg);
string test_output(Integer result[8]);

/* validates closing transactions against a wallet
 * for each transaction:
 * 0. check that balances are correct
 * 1. check that wallet key is integrated correctly
 * 2. check that source is correct
 *    for close_tx_merch, source is txid_merch
 *    for close_tx_escrow, source is txid_escrow
 * 
 * \param[in] w           : wallet object
 * \param[in] close_tx_escrow   : (private) bits of new close transaction (spends from escrow). no more than 1024 bits.
 * \param[in] close_tx_merch    : (private) bits of new close transaction (spends from merchant close transaction). No more than 1024 bits.
 *
 * \return b  : success bit
 */
Bit validate_transactions_local(State_d new_state_d, TxSerialized_d close_tx_escrow_d, TxSerialized_d close_tx_merch_d);

// this is not actually random because I don't seed rand().
// so it produces the same output every time it's compiled.
// would be cool to get something that the same for both parties, but different
// per compilation
// It's also not uniform because of our sketchy modding. #security
string gen_random(const int len) {
  static const char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";

  string s = "";
  for (int i = 0; i < len; ++i) {
    s += alphanum[rand() % (sizeof(alphanum) - 1)];
  }
  return s;
}

/* openssl hard coded test generation

$ xxd /tmp/key
00000000: 766f 6e6a 7571 6662 6c6a 7475 6176 7461  vonjuqfbljtuavta
00000010: 6f6e 6c70 6678 6e66 767a 6c79 7671 6368  onlpfxnfvzlyvqch
00000020: 6d67 7369 6c72 6974 7578 736f 6667 7263  mgsilrituxsofgrc
00000030: 6663 7179 6e7a 756c 7a63 7375 746f 686d  fcqynzulzcsutohm
$ xxd /tmp/msg 
00000000: 6463 6a62 7077 666d 7977 6f66 736c 6a79  dcjbpwfmywofsljy
00000010: 6175 637a 6d74 676c 6f77 7962 7464 6c63  auczmtglowybtdlc
00000020: 7865 6d61 7269 7a64 686d 6b7a 6a70 7a73  xemarizdhmkzjpzs
00000030: 6a76 747a 7969 6976 6871 7468 6776 706e  jvtzyiivhqthgvpn
00000040: 657a 6a67 6678 6466 6376 7075 7779 7466  ezjgfxdfcvpuwytf
00000050: 6d6c 7572 7773 6468 6964 686f 7364 616c  mlurwsdhidhosdal
00000060: 7469 6872 6277 7369 6e7a 7667 7376 7879  tihrbwsinzvgsvxy
00000070: 6864 6b7a                                hdkz

$ openssl dgst -sha256 -hmac $(cat /tmp/key) -hex /tmp/msg 
HMAC-SHA256(/tmp/msg)= af4e2daca29f7c6e68d6a0d536eec5a96527650a59506eea815062b782cc99bb
*/

// The msgs we are signing are 116 bytes long, or 29 ints long
void test_end_to_end() {

  uint8_t test_key_bytes[64] = 
    { 0x76, 0x6f, 0x6e, 0x6a, 0x75, 0x71, 0x66, 0x62, 
      0x6c, 0x6a, 0x74, 0x75, 0x61, 0x76, 0x74, 0x61, 
      0x6f, 0x6e, 0x6c, 0x70, 0x66, 0x78, 0x6e, 0x66, 
      0x76, 0x7a, 0x6c, 0x79, 0x76, 0x71, 0x63, 0x68, 
      0x6d, 0x67, 0x73, 0x69, 0x6c, 0x72, 0x69, 0x74, 
      0x75, 0x78, 0x73, 0x6f, 0x66, 0x67, 0x72, 0x63, 
      0x66, 0x63, 0x71, 0x79, 0x6e, 0x7a, 0x75, 0x6c, 
      0x7a, 0x63, 0x73, 0x75, 0x74, 0x6f, 0x68, 0x6d };

  string test_key = "vonjuqfbljtuavtaonlpfxnfvzlyvqchmgsilrituxsofgrcfcqynzulzcsutohm";

  CryptoPP::SecByteBlock key(test_key_bytes, 64);

  string msg = "dcjbpwfmywofsljyauczmtglowybtdlcxemarizdhmkzjpzsjvtzyiivhqthgvpnezjgfxdfcvpuwytfmlurwsdhidhosdaltihrbwsinzvgsvxyhdkz";
  string expected = reference_HMAC_sign(key, msg);
  string actual = run_secure_HMACsign(test_key, msg);

  boost::algorithm::to_lower(expected);
  boost::algorithm::to_lower(actual);

  assert ( expected.compare(actual) == 0);
  assert ( expected.compare("af4e2daca29f7c6e68d6a0d536eec5a96527650a59506eea815062b782cc99bb") == 0 );

  // randomized tests of 116 messages
  for (int i=0; i < 100; i++) {

    // TODO GENERATE RANDOM KEYS
    msg = gen_random(116);
    string expected = reference_HMAC_sign(key, msg);
    string actual = run_secure_HMACsign(test_key, msg);

    boost::algorithm::to_lower(expected);
    boost::algorithm::to_lower(actual);

    assert ( expected.compare(actual) == 0);

  }
  
  cout << "Passed 64 HMAC end-to-end tests." << endl;
}

// reference HMAC implementation by CryptoPP
string reference_HMAC_sign(CryptoPP::SecByteBlock key, string msg) {

  string mac;
  try {
      CryptoPP::HMAC< CryptoPP::SHA256 > hmac(key, key.size());

      CryptoPP::StringSource ss2(msg, true, 
          new CryptoPP::HashFilter(hmac,
              new CryptoPP::StringSink(mac)
          ) // HashFilter      
      ); // StringSource
  }
  catch(const CryptoPP::Exception& e)
  {
      cerr << e.what() << endl;
      exit(1);
  }
  
  string encoded;

  encoded.clear();
  CryptoPP::StringSource ss3(mac, true,
    new CryptoPP::HexEncoder(
        new CryptoPP::StringSink(encoded)
    ) // HexEncoder
  ); // StringSource

  return encoded;
}


// test hmac implementation 
string run_secure_HMACsign(string key, string msg) {

  //TODO A LOT OF THIS IS WRONG 
  string hex_key;

  CryptoPP::StringSource foo(key, true,
      new CryptoPP::HexEncoder (
        new CryptoPP::StringSink(hex_key)));

   string hex_msg;

  CryptoPP::StringSource bar(msg, true,
      new CryptoPP::HexEncoder (
        new CryptoPP::StringSink(hex_msg)));

  string temp;

  HMACKey_l merch_key_l;

  for(int i =0; i<16; i++) {
    temp = hex_key.substr(i*8, 8);
    merch_key_l.key[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  State_l state_l;

  for(int i=0; i<3; i++) {
    temp = hex_msg.substr(i*8, 8);
    state_l.nonce.nonce[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<8; i++) {
    temp = hex_msg.substr((i+3)*8, 8);
    state_l.rl.revlock[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  temp = hex_msg.substr((11)*8, 8);
  state_l.balance_cust = (uint32_t) strtoul(temp.c_str(), NULL, 16);

  temp = hex_msg.substr((12)*8, 8);
  state_l.balance_merch = (uint32_t) strtoul(temp.c_str(), NULL, 16);

  for(int i=0; i<8; i++) {
    temp = hex_msg.substr((i+13)*8, 8);
    state_l.txid_merch.txid[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<8; i++) {
    temp = hex_msg.substr((i+21)*8, 8);
    state_l.txid_escrow.txid[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  } 

  // MPC - run hmac 
  PayToken_d paytoken_d;
  HMACKey_d merch_key_d = distribute_HMACKey(merch_key_l, MERCH);
  State_d state_d = distribute_State(state_l, CUST);
  HMACsign(merch_key_d, state_d, paytoken_d.paytoken);

  Integer hash = composeSHA256result(paytoken_d.paytoken);
  string res = hash.reveal_unsigned(PUBLIC,16);
  while (res.length() < 64) {
    res = '0' + res;
  }

  return res;
}

// make sure new close transactions are well-formed
Bit validate_transactions_local(State_d new_state_d, TxSerialized_d close_tx_escrow_d, TXSerialized_d close_tx_escrow_spend_script_d, TxSerialized_d close_tx_merch_d) {

  // 112 bytes --> 896
  Integer customer_delayed_script_hash_preimage[2][16];

  // OPCODE 0x63a914 || 1 byte of Rev Lock
  customer_delayed_script_hash_preimage[0][0] = Integer(32, 1672025088 /*0x63a91400*/, PUBLIC) | /* First byte of revlock*/(new_state_d.rl.revlock[0] >> 24);

  // 32 bytes of Rev Lock
  customer_delayed_script_hash_preimage[0][1] = (/* last 3 bytes */ new_state_d.rl.revlock[0] << 8) | ( /* first byte of the next int */ new_state_d.rl.revlock[1] >> 24);
  customer_delayed_script_hash_preimage[0][2] = (new_state_d.rl.revlock[1] << 8) | (new_state_d.rl.revlock[2] >> 24);
  customer_delayed_script_hash_preimage[0][3] = (new_state_d.rl.revlock[2] << 8) | (new_state_d.rl.revlock[3] >> 24);
  customer_delayed_script_hash_preimage[0][4] = (new_state_d.rl.revlock[3] << 8) | (new_state_d.rl.revlock[4] >> 24);
  customer_delayed_script_hash_preimage[0][5] = (new_state_d.rl.revlock[4] << 8) | (new_state_d.rl.revlock[5] >> 24);
  customer_delayed_script_hash_preimage[0][6] = (new_state_d.rl.revlock[5] << 8) | (new_state_d.rl.revlock[6] >> 24);
  customer_delayed_script_hash_preimage[0][7] = (new_state_d.rl.revlock[6] << 8) | (new_state_d.rl.revlock[7] >> 24);
  customer_delayed_script_hash_preimage[0][8] = (new_state_d.rl.revlock[7] << 8) | Integer(32, 136 /*0x00000088*/, PUBLIC);

  customer_delayed_script_hash_preimage[0][9] = Integer(32, 553648128, PUBLIC) | merch_dispute_key.key[0] >> 8; //0x21000000 // taking 3 bytes from the key
  customer_delayed_script_hash_preimage[0][10] = (merch_dispute_key.key[0] << 24) | (merch_dispute_key.key[1] >> 8); // byte 4-7
  customer_delayed_script_hash_preimage[0][11] = (merch_dispute_key.key[1] << 24) | (merch_dispute_key.key[2] >> 8); // byte 8-11
  customer_delayed_script_hash_preimage[0][12] = (merch_dispute_key.key[2] << 24) | (merch_dispute_key.key[3] >> 8); // bytes 12-15
  customer_delayed_script_hash_preimage[0][13] = (merch_dispute_key.key[3] << 24) | (merch_dispute_key.key[4] >> 8); // bytes 16-19
  customer_delayed_script_hash_preimage[0][14] = (merch_dispute_key.key[4] << 24) | (merch_dispute_key.key[5] >> 8); // bytes 20-23
  customer_delayed_script_hash_preimage[0][15] = (merch_dispute_key.key[5] << 24) | (merch_dispute_key.key[6] >> 8); // bytes 24-27
  customer_delayed_script_hash_preimage[2][0]  = (merch_dispute_key.key[6] << 24) | (merch_dispute_key.key[7] >> 8); // bytes 28-31
  customer_delayed_script_hash_preimage[2][1]  = (merch_dispute_key.key[7] << 16) | Integer(32, 26368/*0x00006700*/, PUBLIC) | Integer(32,2 /*0x000002*/, PUBLIC); // bytes 32-33 // 0x67

  // This previous last byte and the following to bytes is the delay.  We should talk about how long we want them to be
  customer_delayed_script_hash_preimage[2][2]  = Integer(32, 3473211392 /*0xcf050000*/, PUBLIC) | Integer(32, 45685/*0x0000b275*/, PUBLIC);
  customer_delayed_script_hash_preimage[2][3]  = Integer(32, 553648128 /*0x21000000*/, PUBLIC)  | (customer_output_key.key[0] >> 8);
  customer_delayed_script_hash_preimage[2][4]  = (customer_output_key.key[0] << 24) | (customer_output_key.key[1] >> 8);
  customer_delayed_script_hash_preimage[2][5]  = (customer_output_key.key[1] << 24) | (customer_output_key.key[2] >> 8);
  customer_delayed_script_hash_preimage[2][6]  = (customer_output_key.key[2] << 24) | (customer_output_key.key[3] >> 8);
  customer_delayed_script_hash_preimage[2][7]  = (customer_output_key.key[3] << 24) | (customer_output_key.key[4] >> 8);
  customer_delayed_script_hash_preimage[2][8]  = (customer_output_key.key[4] << 24) | (customer_output_key.key[5] >> 8);
  customer_delayed_script_hash_preimage[2][9]  = (customer_output_key.key[5] << 24) | (customer_output_key.key[6] >> 8);
  customer_delayed_script_hash_preimage[2][10]  = (customer_output_key.key[6] << 24) | (customer_output_key.key[7] >> 8);
  customer_delayed_script_hash_preimage[2][11]  = (customer_output_key.key[7] << 8) | Integer(32, /*0x000068ac*/, PUBLIC);

  customer_delayed_script_hash_preimage[2][12] = Integer(32, 2147483648/*0x80000000*/, PUBLIC); 
  customer_delayed_script_hash_preimage[2][13] = Integer(32, 0, PUBLIC); //0x00000000; 
  customer_delayed_script_hash_preimage[2][14] = Integer(32, 0, PUBLIC); //0x00000000; 
  customer_delayed_script_hash_preimage[2][15] = Integer(32, 896, PUBLIC); 

  Integer customer_delayed_script_hash[8];

  // DO A DOUBLE SHA256

  // 150 bytes
  Integer hash_outputs_preimage[3][16];

  hash_outputs_preimage[0][0] = // first bytes of customer balance
  hash_outputs_preimage[0][1] = // second bytes of customer blanace
  hash_outputs_preimage[0][2] = Integer(32, 570433536 /*0x22002000*/, PUBLIC) | (customer_delayed_script_hash[0] >> 24); // OPCODE and the first byte of the prev hash output
  hash_outputs_preimage[0][3] = (customer_delayed_script_hash[0] << 8) | (customer_delayed_script_hash[1] >> 24); // end of byte 1 and first byte of 2...
  hash_outputs_preimage[0][4] = (customer_delayed_script_hash[1] << 8) | (customer_delayed_script_hash[2] >> 24);
  hash_outputs_preimage[0][5] = (customer_delayed_script_hash[2] << 8) | (customer_delayed_script_hash[3] >> 24);
  hash_outputs_preimage[0][6] = (customer_delayed_script_hash[3] << 8) | (customer_delayed_script_hash[4] >> 24);
  hash_outputs_preimage[0][7] = (customer_delayed_script_hash[4] << 8) | (customer_delayed_script_hash[5] >> 24);
  hash_outputs_preimage[0][8] = (customer_delayed_script_hash[5] << 8) | (customer_delayed_script_hash[6] >> 24);
  hash_outputs_preimage[0][9] = (customer_delayed_script_hash[6] << 8) | (customer_delayed_script_hash[7] >> 24);
  hash_outputs_preimage[0][10] = (customer_delayed_script_hash[7] << 8) |  /*first byte of merch balance >> 24*/;
  hash_outputs_preimage[0][11] =  /*second through 5th bytes of merch balance */;
  hash_outputs_preimage[0][12] =  /* bytes 6,7,8 of merch balance << 8*/ | Integer(32, 16 /*0x00000016*/, PUBLIC);
  hash_outputs_preimage[0][13] = Integer(32, 1310720 /*0x00140000*/, PUBLIC) | (merch_pubkey_hash.hash[0] >> 16);
  hash_outputs_preimage[0][14] = (merch_pubkey_hash.hash[0] << 16) | (merch_pubkey_hash.hash[1] >> 16);
  hash_outputs_preimage[0][15] = (merch_pubkey_hash.hash[1] << 16) | (merch_pubkey_hash.hash[2] >> 16);
  hash_outputs_preimage[1][0]  = (merch_pubkey_hash.hash[2] << 16) | (merch_pubkey_hash.hash[3] >> 16);
  hash_outputs_preimage[1][1]  = (merch_pubkey_hash.hash[3] << 16) | (merch_pubkey_hash.hash[4] >> 16);
  hash_outputs_preimage[1][2]  = (merch_pubkey_hash.hash[4] << 16) | Integer(32, 0 /*0x00000000*/, PUBLIC); //Two bytes of the OP_Return Amount
  hash_outputs_preimage[1][3]  = Integer(32,0,PUBLIC); // middle 4 bytes of OP_RETURN amount
  hash_outputs_preimage[1][4]  = Integer(32,0,PUBLIC) | (new_state_d.rl.revlock[0] >> 16); //32 bytes
  hash_outputs_preimage[1][5]  = (new_state_d.rl.revlock[0] << 16) | (new_state_d.rl.revlock[1] >> 16); //
  hash_outputs_preimage[1][6]  = (new_state_d.rl.revlock[1] << 16) | (new_state_d.rl.revlock[2] >> 16);
  hash_outputs_preimage[1][7]  = (new_state_d.rl.revlock[2] << 16) | (new_state_d.rl.revlock[3] >> 16);
  hash_outputs_preimage[1][8]  = (new_state_d.rl.revlock[3] << 16) | (new_state_d.rl.revlock[4] >> 16);
  hash_outputs_preimage[1][9]  = (new_state_d.rl.revlock[4] << 16) | (new_state_d.rl.revlock[5] >> 16);
  hash_outputs_preimage[1][10] = (new_state_d.rl.revlock[5] << 16) | (new_state_d.rl.revlock[6] >> 16);
  hash_outputs_preimage[1][11] = (new_state_d.rl.revlock[6] << 16) | (new_state_d.rl.revlock[7] >> 16);
  hash_outputs_preimage[1][12] = (new_state_d.rl.revlock[7] << 16) | (customer_output_key.key[0] >> 16); //2
  hash_outputs_preimage[1][13] = (customer_output_key.key[0] << 16) | (customer_output_key.key[1] >> 16); //6
  hash_outputs_preimage[1][14] = (customer_output_key.key[1] << 16) | (customer_output_key.key[2] >> 16); //10
  hash_outputs_preimage[1][15] = (customer_output_key.key[2] << 16) | (customer_output_key.key[3] >> 16); //14
  hash_outputs_preimage[2][0]  = (customer_output_key.key[3] << 16) | (customer_output_key.key[4] >> 16); //18
  hash_outputs_preimage[2][1]  = (customer_output_key.key[4] << 16) | (customer_output_key.key[5] >> 16); //22
  hash_outputs_preimage[2][2]  = (customer_output_key.key[5] << 16) | (customer_output_key.key[6] >> 16); //26
  hash_outputs_preimage[2][3]  = (customer_output_key.key[6] << 16) | (customer_output_key.key[7] >> 16); //30
  hash_outputs_preimage[2][4]  = (customer_output_key.key[7] << 16) | (customer_output_key.key[8] >> 16) | Integer(32,128 /*0x00000080*/, PUBLIC); //33

  hash_outputs_preimage[2][5]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][6]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][7]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][8]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][9]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][10]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][11]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][12]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][13]  = Integer(32,0,PUBLIC);
  hash_outputs_preimage[2][14] = Integer(32, 0, PUBLIC); //0x00000000; 
  hash_outputs_preimage[2][15] = Integer(32, 1200, PUBLIC); 

  Integer hash_outputs[8];

  // TODO COMPUTE THE DOUBLE HASH

  // The total preimage is 228 bytes
  Integer total_preimage[4][16];

  total_preimage[0][0] = Integer(32, 33554432 /*0x02000000*/, PUBLIC);
  total_preimage[0][1] = new_state_d.hashprevouts.txid[0];
  total_preimage[0][2] = new_state_d.hashprevouts.txid[1];
  total_preimage[0][3] = new_state_d.hashprevouts.txid[2];
  total_preimage[0][4] = new_state_d.hashprevouts.txid[3];
  total_preimage[0][5] = new_state_d.hashprevouts.txid[4];
  total_preimage[0][6] = new_state_d.hashprevouts.txid[5];
  total_preimage[0][7] = new_state_d.hashprevouts.txid[6];
  total_preimage[0][8] = new_state_d.hashprevouts.txid[7];

  total_preimage[0][9]  =  Integer(32, 1001467945  /*0x3bb13029*/, PUBLIC);
  total_preimage[0][10] =  Integer(32, 3464175445 /*0xce7b1f55*/, PUBLIC);
  total_preimage[0][11] =  Integer(32, 2666915655 /*0x9ef5e747*/, PUBLIC);
  total_preimage[0][12] =  Integer(32, 4239147935 /*0xfcac439f*/, PUBLIC);
  total_preimage[0][13] =  Integer(32,  341156588 /*0x1455a2ec*/, PUBLIC);
  total_preimage[0][14] =  Integer(32, 2086603191 /*0x7c5f09b7*/, PUBLIC);
  total_preimage[0][15] =  Integer(32,  579893598 /*0x2290795e*/, PUBLIC);
  total_preimage[1][0]  =  Integer(32, 1885753412  /*0x70665044*/, PUBLIC);

  total_preimage[1][1] = new_state_d.txid_escrow.txid[0];
  total_preimage[1][2] = new_state_d.txid_escrow.txid[1];
  total_preimage[1][3] = new_state_d.txid_escrow.txid[2];
  total_preimage[1][4] = new_state_d.txid_escrow.txid[3];
  total_preimage[1][5] = new_state_d.txid_escrow.txid[4];
  total_preimage[1][6] = new_state_d.txid_escrow.txid[5];
  total_preimage[1][7] = new_state_d.txid_escrow.txid[6];
  total_preimage[1][8] = new_state_d.txid_escrow.txid[7];

  total_preimage[1][9]  = Integer(32, 1196564736/*0x47522100*/, PUBLIC) | (merch_pub_key.key[0] >> 24);
  total_preimage[1][10] = (merch_pub_key.key[0] << 8) | (merch_pub_key.key[1] >> 24);
  total_preimage[1][11] = (merch_pub_key.key[1] << 8) | (merch_pub_key.key[2] >> 24);
  total_preimage[1][12] = (merch_pub_key.key[2] << 8) | (merch_pub_key.key[3] >> 24);
  total_preimage[1][13] = (merch_pub_key.key[3] << 8) | (merch_pub_key.key[4] >> 24);
  total_preimage[1][14] = (merch_pub_key.key[4] << 8) | (merch_pub_key.key[5] >> 24);
  total_preimage[1][15] = (merch_pub_key.key[5] << 8) | (merch_pub_key.key[6] >> 24);
  total_preimage[2][0]  = (merch_pub_key.key[6] << 8) | (merch_pub_key.key[7] >> 24);
  total_preimage[2][1]  = (merch_pub_key.key[7] << 8) | (merch_pub_key.key[8] >> 24);
  total_preimage[2][2]  = Integer(32, 553648128 /*0x21000000*/, PUBLIC) | (cust_pub_key.key[0] >> 8);  // first three bytes of the cust public key
  // 30 more bytes of key
  total_preimage[2][3]  = (cust_pub_key.key[0] << 24)| (cust_pub_key.key[1] >> 8); 
  total_preimage[2][4]  = (cust_pub_key.key[1] << 24)| (cust_pub_key.key[2] >> 8); 
  total_preimage[2][5]  = (cust_pub_key.key[2] << 24)| (cust_pub_key.key[3] >> 8); 
  total_preimage[2][6]  = (cust_pub_key.key[3] << 24)| (cust_pub_key.key[4] >> 8); 
  total_preimage[2][7]  = (cust_pub_key.key[4] << 24)| (cust_pub_key.key[5] >> 8); 
  total_preimage[2][8]  = (cust_pub_key.key[5] << 24)| (cust_pub_key.key[6] >> 8); 
  total_preimage[2][9]  = (cust_pub_key.key[6] << 24)| (cust_pub_key.key[7] >> 8); 
  total_preimage[2][10] = (cust_pub_key.key[7] << 24)| (cust_pub_key.key[8] >> 8) | Integer(32, 21166/*0x000052ae*/, PUBLIC);

  total_preimage[2][11] = //first bytes of input ammount = Balance + Balance
  total_preimage[2][12] = //second bytes of input ammount = Balance + Balance

  total_preimage[2][13] = Integer(32, 4294967295 /*0xffffffff*/, PUBLIC);

  total_preimage[2][13] = hash_outputs[0];
  total_preimage[2][14] = hash_outputs[1];
  total_preimage[2][15] = hash_outputs[2];
  total_preimage[3][0]  = hash_outputs[3];
  total_preimage[3][1]  = hash_outputs[4];
  total_preimage[3][2]  = hash_outputs[5];
  total_preimage[3][3]  = hash_outputs[6];
  total_preimage[3][4]  = hash_outputs[7];

  total_preimage[3][5]  = Integer(32, 0 /*0x00000000*/, PUBLIC);
  total_preimage[3][6]  = Integer(32, 16777216 /*0x01000000*/, PUBLIC);

  total_preimage[3][7]   = Integer(32, 2147483648/*0x80000000*/, PUBLIC); 
  total_preimage[3][8]   = Integer(32, 0, PUBLIC);
  total_preimage[3][9]   = Integer(32, 0, PUBLIC);
  total_preimage[3][10]  = Integer(32, 0, PUBLIC);
  total_preimage[3][11]  = Integer(32, 0, PUBLIC);
  total_preimage[3][12]  = Integer(32, 0, PUBLIC);
  total_preimage[3][13]  = Integer(32, 0, PUBLIC);
  total_preimage[3][14]  = Integer(32, 0, PUBLIC); //0x00000000; 
  total_preimage[3][15]  = Integer(32, 912, PUBLIC); 

  // TODO COMPUTE THE DOUBLE HASH!
  // THIS IS THE ESCROW TRANSACTION

  Integer escrow_digest[8];


  // // Escrow amount.  Check from state
  // b = (b|close_tx_escrow_d.tx[74].equals(new_state_d.balance_escrow.balance[0]));
  // b = (b|close_tx_escrow_d.tx[75].equals(new_state_d.balance_escrow.balance[1]));

  // Integer sequence_field(32, 4294967295, PUBLIC);

  // b = (b|close_tx_escrow_d.tx[76].equals(sequence_field))

  // Integer nlocktime_field(32, 0, PUBLIC);
  // Integer sighashtype_field(32, 16777216, PUBLIC);

  // b = (b|close_tx_escrow_d.tx[85].equals(nlocktime_field));
  // b = (b|close_tx_escrow_d.tx[86].equals(sighashtype_field));

  return b;
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