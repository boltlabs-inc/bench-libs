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

void validate_signature(string secret, string msg, string sig) {
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privkey;

  CryptoPP::HexDecoder decoder;
  decoder.Put((byte *)&secret[0], secret.size());
  decoder.MessageEnd();

  CryptoPP::Integer x;
  x.Decode(decoder, decoder.MaxRetrievable());

  privkey.Initialize(ASN1::secp256k1(), x);
  bool result = privkey.Validate(prng, 3);
  if (!result) {
    cout << "bad private key" << endl;
    return;
  }

  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubkey;
  privkey.MakePublicKey(pubkey);
  result = pubkey.Validate(prng, 3);
  if (!result) {
    cout << "bad public key" << endl;
    return;
  }

  // TODO: fails because this msg is already hashed. We need the original for this to validate properly.
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier( pubkey );
  CryptoPP::StringSource ss(sig + msg, true,
    new CryptoPP::SignatureVerificationFilter(
      verifier,
      new CryptoPP::ArraySink( (byte*)&result, sizeof(result) )));

  if (!result) {
    cout << "bad signature" << endl;
    return;
  }

  cout << "everything ok" << endl;
  




}

void test_vectors_from_file() {
  // read from file
  string secret = "0f3d6322ea090bcae3d548bd866ed18162c391e865c3556d52d4eb9416d0cb08";
  string msg = "c74a413f949209218a62b4b20726a8c2d222c2f0b0e51858c25aa3e8cf1a52f3";
  string sig = "1808a755daa0c01ef8d5be1b811af30061782983688489ab0613a00aaaa7db617f80f9c507d8cb848adbbeb3de3a8e3375f2f12d0c1a468153b48c17cfd7f978";
  string r = "7913485180834049136650668178914227957561066370461353605956886480359654810771";
  string k_inv = "111493547342612901036345801958286580672694014433743061827635735207193071264317";


  secret = "2c18aec8b85af7699420c0231c9aafad1c0479fef21c3e89156eee834d8272c7";
  msg = "f7cef157ecd82e3b303ed0efb04b7c03a906e2575ba4f3631d28a75318bfc0bf";
  sig = "0d60660d1cca84ad7846aa715512b8d73b88ad2b11f1edc3ee552d645421d3c317654ec947aa7807b06adb554d160a0daa701c98fef9641a04a975ee0193576b";
  r = "6050388681439922606531770736235994049418759587930168486780873242865549038531";
  k_inv = "115439820451179298612727241820335060148401902339560995563654340803756537405725";

  validate_signature(secret, msg, sig);
  
  cout << change_base(r,10,16) << endl;;


  /*
  msg = "68b0424486651f78748e31f2e0ac30bc3a8e8a3ebebf492244b129a5d95bba8e";
  sig = "6b9a32e3c12d4606c9426dfed4db2705f6de26a4a6705a86cec9f4dc2f46f48d44eb31aa0ca42693ea750ae28e5c57077c16e658ad402d94ca105d14e28600be";
  r = "48669920473954504460648095582690834937933402865433997809507510532130143138957";
  k_inv = "78806992654404740588773615297361166733554192253349232660443284396762193121119";
  */

  msg = change_base(msg, 16, 10);
  Integer e(256, msg, PUBLIC);
  
  EcdsaPartialSig_l psl;
  psl.r = r;
  psl.k_inv = k_inv;
  EcdsaPartialSig_d psd = distribute_EcdsaPartialSig(psl);

  Integer result = sign_hashed_msg(e, psd);
  string actual = result.reveal_unsigned(PUBLIC);
  actual = change_base(actual, 10, 16);

  string expected = sig.substr(64);
  cout << "len: " << expected.length() << endl;

  cout << "actual   : " << actual << endl;
  cout << "expected : " << expected << endl;

  cout << "failed one test" << endl;
  
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

  test_vectors_from_file();

  delete io;
  return 0;
}
