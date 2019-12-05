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
#include "build_tokens/sha256.h"
using namespace emp;
using namespace std;

// crypto++ headers
#include "cryptopp/asn.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/filters.h"
#include "cryptopp/oids.h"
#include "cryptopp/osrng.h"
namespace ASN1 = CryptoPP::ASN1;
#define byte unsigned char

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

  const CryptoPP::Integer& x = privatekey.GetPrivateExponent();

  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey publickey;
  privatekey.MakePublicKey(publickey);

  if (! publickey.Validate(prng,3)){
    return "public key failed";
  }

  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(privatekey);
  string message = "oh no why is this so hard";
  string sig;

  CryptoPP::StringSource s(message, true,
    new CryptoPP::SignerFilter (prng,
      signer,
      new CryptoPP::StringSink( sig )));

    
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

// TODO: figure out best way to do modular bignum arithmetic in C.
// compute partial sigs from test vectors on the internet
// https://crypto.stackexchange.com/questions/784/are-there-any-secp256k1-ecdsa-test-examples-available
// 
void test_vectors() {
  int k = 1;
  
  
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
