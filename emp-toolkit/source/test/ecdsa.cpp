/*
 * TODO
 *
 * This will run end-to-end tests on the ecdsa functionality
 * (in build_token/ecdsa.*)
 *
 * 1. generate test data (using reference impl in from rust)
 * 2. run under MPC
 * 3. compare results
 *
 */

#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
#include "build_tokens/ecdsa.h"
using namespace emp;
using namespace std;

#include "cryptopp/eccrypto.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/oids.h"
#include "cryptopp/osrng.h"
#define byte unsigned char
namespace ASN1 = CryptoPP::ASN1;

bool validate_signature(string secret, string msg, string sig) {
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privkey;

  // parse secret into private key
  CryptoPP::HexDecoder decoder;
  decoder.Put((byte *)&secret[0], secret.size());
  decoder.MessageEnd();

  CryptoPP::Integer x;
  x.Decode(decoder, decoder.MaxRetrievable());

  privkey.Initialize(ASN1::secp256k1(), x);
  bool result = privkey.Validate(prng, 3);
  if (!result) {
    cout << "bad private key" << endl;
    return result;
  }

  // generate corresponding public key
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubkey;
  privkey.MakePublicKey(pubkey);
  result = pubkey.Validate(prng, 3);
  if (!result) {
    cout << "bad public key" << endl;
    return result;
  }

  // apply signature verification to message + signature
  // TODO: fails because this msg is already hashed. We need the original for this to validate properly.
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier( pubkey );
  CryptoPP::StringSource ss(sig + msg, true,
    new CryptoPP::SignatureVerificationFilter(
      verifier,
      new CryptoPP::ArraySink( (byte*)&result, sizeof(result) )));

  if (!result) {
    // cout << "bad signature" << endl;
    return result;
  }

  cout << "everything ok" << endl;
  return true;
}


void test_hardcoded_vector() {
  // TODO: read from file
  string secret = "eaf987c1c4c075c9bcd9f6c9cc0f6628f3b96dec433363992ad4b3347e5669f3";
  string hashedmsg = "469457f5921cb642d5df1854342507b3c0df6c8f5b352fc85de05ac0a5cb26c8";
  string sig = "4df58e74231e5ba8fee4d34ad79a0a4652400dcf2662f0801d588f8cff214bb36e18b5ddc827927164eec163096f7f4f7c6f55e2a8308bb75eb7808aabea9332";
  string r = "26463205901945641209230855182233034246646264939878964221079776711177665272924";
  string k_inv = "36979145525970282406643140119499976117570447117404397467172974627410940786338";

  // make sure rust-generated signature is correct
  bool result = validate_signature(secret, hashedmsg, sig);
  if (!result) {
    //cout << "signature validation failed" << endl;
  }

  // format message correctly
  hashedmsg = change_base(hashedmsg, 16, 10);
  Integer e(256, hashedmsg, PUBLIC);
  
  // format partial signature
  EcdsaPartialSig_l psl;
  psl.r = r;
  psl.k_inv = k_inv;
  EcdsaPartialSig_d psd = distribute_EcdsaPartialSig(psl);

  // compute and parse result
  string actual = sign_hashed_msg(e, psd).reveal_unsigned(PUBLIC);
  actual = change_base(actual, 10, 16);
  while (actual.length() < 64) {
    actual = '0' + actual;
  }

  // parse expected result
  string expected = sig.substr(64);

  assert ( actual.compare(expected) == 0 );

  cout << "passed one test" << endl;
}


int main(int argc, char** argv) {
  // run in semihonest library
  int port, party;
  if (argc != 2) {
    cerr << "ERROR: not enough args" << endl;
    return 1;
  }
  party = atoi(argv[1]);
  port = 12345;
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  test_hardcoded_vector();

  delete io;
  return 0;
}
