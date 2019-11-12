#include <typeinfo>
#include "ecdsa.h"


// computes SHA256 hash of the input
// todo; maybe require this in a different format 
// (e.g. padded and in blocks)
Integer signature_hash(Integer m) {
  return m;
}

// hard-coded conversion of secp256k1 point order 
// (e.g. modulus)
// you can go check that these have the same value
void get_ECDSA_params(string *q) {
  string qhex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
  *q = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
}

// ecdsa-signs a message based on the given parameters
// parameters here are appended -c because they're in the clear
// q : subgroup order
// rx, ry : public key point on curve
// sk : private key integer
// ki : private key
struct ECDSA_sig ecdsa_sign(//int rxc, int ryc,
                     int skc, int kic,
                     int mc) {

  // shared inputs: ECDSA params
  // q is public
  // (r_x, r_y) = k*G. merchant chooses k and shares these in the clear
  string qcs;
  get_ECDSA_params(&qcs);
  Integer q(257, qcs, PUBLIC);
  // Integer rx(QLEN, rxc, PUBLIC);
  // Integer ry(QLEN, ryc, PUBLIC);

  // merchant inputs
  // sk : r_x * x mod q
  // k_inv : inverse of k (explained above)
  Integer sk(257, skc, MERCH);
  Integer k_inv(513, kic, MERCH);

  // customer inputs
  // m : message (limited to 1024 bits because that's all we can hash)
  Integer m(1024, mc, CUST);

  // hash input
  Integer e = signature_hash(m);
  e.resize(257, true);
  e = e % q;

  // can we keep q in the clear and use it as the modulus?
  Integer s = e + sk;
  s = s % q;

  s.resize(513,true);
  q.resize(513,true);
  s = k_inv * s;
  s = s % q;

  s.resize(256,true);

  struct ECDSA_sig signature;
  //signature.rx = rx;
  //signature.ry = ry;
  signature.s = s;
  return signature;
}


// very bad fake test
void test_signature() {
  ECDSA_sig es = ecdsa_sign(1,1,1);
  cout << "signature is " << es.s.reveal<int>(PUBLIC) << endl;
}

