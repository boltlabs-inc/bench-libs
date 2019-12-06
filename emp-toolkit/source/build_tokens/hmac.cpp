#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens-misc.h"
#include "hmac.h"
#include "sha256.h"
using namespace emp;
using namespace std;

/* This function executes the inner hash of the HMAC algorithm
 * The resulting hash is returned in innerhashresult
 * We are computing SHA256(  ( key ^ ipad ) || state )
 * This requires 3 SHA256 rouns (state is ~928 bits and key^ipad is 512bits)
 */
void innerhash(HMACKey_d key, State_d state, Integer innerhashresult[8]) {

  // Preparing the buffer for the hash input

  Integer message[3][16];

  // XORing the key with inner pad
  for(int i=0; i<16; i++) {
    message[0][i] = key.key[i] ^ ipad_int;
  }

  // Packing the state structure 
  // nonce is 96 bits long
  message[1][0] = state.nonce.data[0];
  message[1][1] = state.nonce.data[1];
  message[1][2] = state.nonce.data[2];
  // message[1][3] = state.nonce.data[3];  

  // Rev lock is 256 bits, but is currently stored in a bit array
  // 256/32 = 8
  message[1][3] = state.rl.revlock[0];
  message[1][4] = state.rl.revlock[1];
  message[1][5] = state.rl.revlock[2];
  message[1][6] = state.rl.revlock[3];
  message[1][7] = state.rl.revlock[4];
  message[1][8] = state.rl.revlock[5];
  message[1][9] = state.rl.revlock[6];
  message[1][10] = state.rl.revlock[7];

  // Blance escrowomer -- 1 int
  message[1][11] = state.balance_escrow;
  message[1][12] = state.balance_merch;

  // Starting the txid_merch.  96 bits fit in this block
  message[1][13] = state.txid_merch[0];
  message[1][14] = state.txid_merch[1];
  message[1][15] = state.txid_merch[2];

  // continue with the txid_merch in the 3rd block
  message[2][0] = state.txid_merch[3];
  message[2][1] = state.txid_merch[4];
  message[2][2] = state.txid_merch[5];
  message[2][3] = state.txid_merch[6];
  message[2][4] = state.txid_merch[7];

  // Now packing txid_escrow
  message[2][5] = state.txid_escrow[0];
  message[2][6] = state.txid_escrow[1];
  message[2][7] = state.txid_escrow[2];
  message[2][8] = state.txid_escrow[3];
  message[2][9] = state.txid_escrow[4];
  message[2][10] = state.txid_escrow[5];
  message[2][11] = state.txid_escrow[6];
  message[2][12] = state.txid_escrow[7];

  // a single 1 bit, followed by 0's
  // 64 bit big-endian representation of 928
  message[2][13] = 0x80000000;
  message[2][14] = 0x00000000;
  message[2][15] = 0x000003a0;

  computeSHA256(message, innerhasresult);
}

/* This function execute the outer hash of the HMAC algorithm
 * the resulting hash is returned in outerhashresult
 * We are computing SHA256( ( key ^ opad ) || innerhashresult )
 */
void outerhash(HMACKey key, Integer innerhashresult[8], Integer outerhashresult[8]) {

  // Preparing the buffer for the hash input
  
  Integer message[2][16];

  // XORing the key with inner pad
  
  for(int i=0; i<16; i++) {
    message[0][i] = key.key[i] ^ opad_int;
  }
  
  for(int i=0; i<8; i++) {
    message[1][i] = innerhashresult[i];
  }
  
  //padding and length bits
  message[1][9]  = 0x80000000;
  message[1][10] = 0x00000000;
  message[1][11] = 0x00000000;
  message[1][12] = 0x00000000; 
  message[1][13] = 0x00000000;
  
  // 64 bit big-endian representaiton of 768
  message[1][14] = 0x00000000; 
  message[1][15] = 0x00000300; 

  computeSHA256(message, outerhasresult);
} 
  
  
void HMACsign(HMACKey_d merch_key, State_d state, PayToken_d paytoken) {
  
  Integer innerhashresult[8];
  
  innerhash(merch_key, state, innerhashresult);
  
  outerhash(merch_key, innerhashresult, paytoken.paytoken);
} 