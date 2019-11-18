#include <typeinfo>
#include "ecdsa.h"
#include "sha256.h"

// computes SHA256 hash of the input
// first, converts bit-array to uint blocks as required by sha256
// (big-endian bit shifts; maybe they're in the wrong order?
//  TODO make some test vectors, seriously)
//
Integer signature_hash(bool msg[1024]) {
  uint message[2][16] = {0};
  uint shft = 0;
  uint block = 0;
  uint byte = 0;
  uint build = 0;
  for (int i=1023; i>0; i--) {
    build |= msg[i] << shft;

    shft++;
    if (shft == 32) {
      message[block][byte] = build;
      byte++;
      build = 0;
      shft = 0;
    }
    if (byte == 16) {
      cout << "built message block " << block << endl;
      block++;
      byte = 0;
    }
  }
  cout << "finished building message" << endl;
  
  //UInteger result[8];
  Integer result[8];
  computeSHA256(message, result);
  
  cout << "successful hash of message" << endl;

  for (int j=0; j < 8; j++) {
    cout << "\t" << get_bitstring(result[j]) << endl;
  }
  //Integer intlen(256,32,PUBLIC);
  //Integer squash(256, 0, PUBLIC);
  //squash = squash | result[0];
  //cout << "one chunk: " << change_base(get_bitstring(squash),2,16) << endl;
  //squash = (squash << intlen) | result[1];
  cout << "resized result" << endl;


  string res = "";
  for (int r=0; r<7; r++){
    res += get_bitstring(result[r]);
  }

  res = change_base(res, 2, 16);
  cout <<"ecdsa hash: " << res << endl;

  // TODO: figure out correct output format!!

  //return message;
  Integer a(256, "123", PUBLIC);
  return a;
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
  //UInteger m = makeUInteger(msg, 1024, 1024, CUST);

  // hash input
  cout << "about to hash" << endl;
  Integer e = signature_hash(msg);
  cout << "finished hash" << endl;
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


