/*
 * TODO
 *
 * This will run end-to-end tests on the ecdsa functionality
 * (in build_token/ecdsa.*)
 *
 * 1. generate test data (using reference impl in ecdsa_testvector.py)
 * 2. run under MPC
 * 3. compare results
 *
 */

#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
#include "build_tokens/ecdsa.h"
using namespace emp;
using namespace std;

// crypto++ headers
#include "cryptopp/aes.h"
#include "cryptopp/asn.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/modes.h"
#include "cryptopp/oids.h"
#include "cryptopp/osrng.h"
#include "cryptopp/rdrand.h"
#include "cryptopp/secblock.h"
#define byte unsigned char
namespace ASN1 = CryptoPP::ASN1;

// reference ecdsa implementation from cryptopp
// I don't know how to extract the partial signature we need for emp-toolkit from this
string test_reference() {
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privatekey;

  privatekey.Initialize( prng, ASN1::secp256k1() );
  bool result = privatekey.Validate( prng, 3);
  if( !result ) {
    return "private key failed";
  }

  //const CryptoPP::Integer& x = privatekey.GetPrivateExponent();

  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publickey;
  privatekey.MakePublicKey(publickey);

  if (! publickey.Validate(prng,3)){
    return "public key failed";
  }

  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(privatekey);

  publickey.getTrapdoorFunctionInterface();

  string message = "oh no why is this so hard";
  size_t siglen = signer.MaxSignatureLength();
  string sig(siglen, 0x00);

  siglen = signer.SignMessage(prng, (const byte*)&message[0], message.size(), (byte*)&sig[0] );

  cout << "siglen: " << siglen << endl;
  /*
  CryptoPP::StringSource s(message, true,
    new CryptoPP::SignerFilter (prng,
      signer,
      new CryptoPP::StringSink( sig )));
*/
    
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(publickey);
  CryptoPP::StringSource ss(sig+message, true,
    new CryptoPP::SignatureVerificationFilter(
      verifier, 
      new CryptoPP::ArraySink( (byte*) &result, sizeof(result) )));

  if (!result) {
    return "verification failed";
  }

  return "wow ok";
}


// this is one way to generate identical prngs.
// we can use this if I figure out how SignMessage() above uses the PRNG to generate k.
void test_replicable_rng() {
  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng;
  CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption prng2;

  CryptoPP::SecByteBlock seed(32+16);
  CryptoPP::OS_GenerateRandomBlock(false, seed, seed.size());

  prng.SetKeyWithIV(seed, 32, seed+32, 16);
  prng2.SetKeyWithIV(seed, 32, seed+32, 16);
  string k,l;

  CryptoPP::SecByteBlock key(16);
  CryptoPP::SecByteBlock lok(16);

  prng.GenerateBlock(key, key.size());
  prng2.GenerateBlock(lok, lok.size());

  CryptoPP::HexEncoder hex(new CryptoPP::StringSink(k));
  hex.Put(key, key.size());
  hex.MessageEnd();

  hex.Detach(new CryptoPP::StringSink(l));
  hex.Put(lok, lok.size());
  hex.MessageEnd();

  cout << "Key: " << k << endl;
  cout << "Lok: " << l << endl;

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

  test_reference();
  // run end-to-end tests
  //test_vectors();


  delete io;
  return 0;
}
