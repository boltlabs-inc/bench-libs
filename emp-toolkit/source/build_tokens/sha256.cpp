#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
#include "sha256.h"
using namespace emp;
using namespace std;

/* implementation of SHA256 from FIPS PUB 180-4 
 * with the following modifications
 * - processes only a fixed length input (BLOCKS)
 * - assumes padding already exists
 */


Integer ROR32(Integer x, Integer n) {
  Integer thirtytwo(BITS, 32, PUBLIC);
  return (x >> n) | (x << (thirtytwo - n));
}
Integer ROR32(Integer x, uint n) {
  Integer shiftamt(BITS, 32 - n, PUBLIC);
  return (x >> n) | (x << shiftamt);
}
uint ROR32(uint x, uint n) {
  return ((x >> n) | (x << (32 - n)));
}


void initSHA256(Integer k[64], Integer H[8]) {
  for(int i=0; i<64; i++) {
    k[i] = Integer(BITS, k_clear[i], PUBLIC);
  }
  for(int i=0; i<8; i++) {
    H[i] = Integer(BITS, IV_clear[i], PUBLIC);
  }
}

string get_bitstring(Integer x) {
  string s = "";
  for(int i=0; i<x.size(); i++) {
    s = (x[i].reveal<bool>(PUBLIC) ? "1" : "0") + s;
  }
  return s;
}

// result is 8 32-bit integers
// hash   is 1 256-bit integer
// hash = result[0] || result[1] || ... || result[7]
Integer composeSHA256result(Integer result[8]) {
  Integer thirtytwo(256, 32, PUBLIC);
  result[0].resize(256, false);
  Integer hash = result[0];
  for(int i=1; i<8; i++) {
    result[i].resize(256, false);
    hash = (hash << thirtytwo) | result[i];
  }
  return hash;
}

/* computes sha256 for a 2-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256(uint message[BLOCKS][16], Integer result[8]) {

  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer a,b,c,d,e,f,g,h;
  Integer w[BLOCKS][64];
  // initialize message schedule
  for (int i=0; i<BLOCKS; i++) {
    for(size_t t=0; t<16; t++) {
      // todo: figure out who the message belongs to
      w[i][t] = Integer(BITS, message[i][t], CUST);
    }
  }

  initSHA256(k, H);

  for (int i=0; i<BLOCKS; i++) {

    // prepare message schedule

    // 1. Prepare the message schedule, {Wt}
    for(size_t t = 0 ; t <= 63 ; t++)
    {
      if( t<=15 ) {
       // skip, we initialized this above 
      }
      else
        // untested alert: maybe the message scheduling matrix is doing something weird 
        // for multiple block inputs. Only tested for one block input.
        w[i][t] = SIGMA_LOWER_1(w[i][t-2]) + w[i][t-7] + SIGMA_LOWER_0(w[i][t-15]) + w[i][t-16];
    }

    // 2. Initialize working variables
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    // 3. Compress: update working variables
    for (int t=0; t < 64; t++) {
      Integer temp1 = h + SIGMA_UPPER_1(e) + CH(e, f, g) + k[t] + w[i][t];
      Integer temp2 = SIGMA_UPPER_0(a) + MAJ(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    // 4. Set new hash values
    H[0] = H[0] + a;
    H[1] = H[1] + b;
    H[2] = H[2] + c;
    H[3] = H[3] + d;
    H[4] = H[4] + e;
    H[5] = H[5] + f;
    H[6] = H[6] + g;
    H[7] = H[7] + h;
  }

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}


/* computes sha256 for a 2-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256_d(Integer message[BLOCKS][16], Integer result[8]) {

  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer a,b,c,d,e,f,g,h;
  Integer w[BLOCKS][64];
  // initialize message schedule
  for (int i=0; i<BLOCKS; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<BLOCKS; i++) {

    // prepare message schedule

    // 1. Prepare the message schedule, {Wt}
    for(size_t t = 0 ; t <= 63 ; t++)
    {
      if( t<=15 ) {
       // skip, we initialized this above 
      }
      else
        // untested alert: maybe the message scheduling matrix is doing something weird 
        // for multiple block inputs. Only tested for one block input.
        w[i][t] = SIGMA_LOWER_1(w[i][t-2]) + w[i][t-7] + SIGMA_LOWER_0(w[i][t-15]) + w[i][t-16];
    }

    // 2. Initialize working variables
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    // 3. Compress: update working variables
    for (int t=0; t < 64; t++) {
      Integer temp1 = h + SIGMA_UPPER_1(e) + CH(e, f, g) + k[t] + w[i][t];
      Integer temp2 = SIGMA_UPPER_0(a) + MAJ(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    // 4. Set new hash values
    H[0] = H[0] + a;
    H[1] = H[1] + b;
    H[2] = H[2] + c;
    H[3] = H[3] + d;
    H[4] = H[4] + e;
    H[5] = H[5] + f;
    H[6] = H[6] + g;
    H[7] = H[7] + h;
  }

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}