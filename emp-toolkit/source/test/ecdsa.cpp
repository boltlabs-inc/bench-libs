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

void test_vectors_from_file() {
  // read from file
  string msg = "e4a89eb40da775f8d65828c6cfac3609742fd550c568744c38dd755d24cea567";
  string expected = "304402207a314983197ca025e5c212cba99e65288923cc9bef8bcd7035d2a61d64f44e1c02207ba13f36a001239d4d653c5d3438bd0b107df24c50a82f10f0e44523a0af34c5";
  string r = "108792476108599305057612221643697785065475034835954270988586688301027220077907";
  string k_inv = "44657876998057202178264530375095959644163723589174927475562391733096641768603";


  Integer e(256, msg, PUBLIC);
  
  EcdsaPartialSig_l psl;
  psl.r = r;
  psl.k_inv = k_inv;
  EcdsaPartialSig_d psd = distribute_EcdsaPartialSig(psl);

  Integer result = sign_hashed_msg(e, psd);
  string actual = result.reveal<string>(PUBLIC);

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
