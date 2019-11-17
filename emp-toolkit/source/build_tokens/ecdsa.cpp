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
string get_ECDSA_params() {
  string qhex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
  return "115792089237316195423570985008687907852837564279074904382605163141518161494337";
}

// ecdsa-signs a message based on the given parameters
// parameters here are appended -c because they're in the clear
// mc : message text (in the clear)
// pubsig : partial ecdsa signature in the clear (see token.h)
struct ECDSA_sig ecdsa_sign(bool msg[1024], EcdsaPartialSig pubsig) {

  // shared inputs: ECDSA params
  // q is public
  string qcs = get_ECDSA_params();
  Integer q(257, qcs, PUBLIC);

  // merchant inputs
  PrivateEcdsaPartialSig partialsig = setEcdsaPartialSig(pubsig);
  // cout << "partialsig " << partialsig.r.reveal<int>(PUBLIC) << endl;

  // customer inputs
  // m : message (limited to 1024 bits because that's all we can hash)
  Integer m = makeInteger(msg, 1024, 1024, CUST);

  // hash input
  Integer e = signature_hash(m);
  e.resize(257, true);
  e = e % q;

  // can we keep q in the clear and use it as the modulus?
  Integer s = e + partialsig.r;
  s = s % q;

  s.resize(513,true);
  q.resize(513,true);
  s = partialsig.k_inv * s;
  s = s % q;

  s.resize(256,true);

  struct ECDSA_sig signature;
  signature.s = s;

  cout << "signature is " << signature.s.reveal<string>(PUBLIC) << endl;
  return signature;
}


// very bad fake test
void test_signature() {
  EcdsaPartialSig s;
  bool msg[1024] = {0};
  ECDSA_sig es = ecdsa_sign(msg, s);
  cout << "signature is " << es.s.reveal<int>(PUBLIC) << endl;
}


