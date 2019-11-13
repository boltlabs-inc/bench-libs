#include <typeinfo>
#include "ecdsa.h"
#include "sha256.h"
#include "tokens.h"

using namespace std;

// old main functions -- don't use
int sha256_main(int argc, char** argv);
int ecdsa_main(int argc, char** argv);

/* 
 * Test main for token generation
 * generates fake data for now.
 */
int main(int argc, char** argv) {

  assert (argc == 2);
  int party = atoi(argv[1]);
  int port = 12345;

  if (party == MERCH) {
	PubKey pkM;
	RevLock rl;
	EcdsaPartialSig sig;
	bool mask[256];
	build_masked_tokens_merch(
	  pkM, nullptr, nullptr, rl, port, "127.0.0.1",
	  mask, mask, sig, sig, sig);
  } else {
	PubKey pkM;
	RevLock rl;
	State w;
	bool tx[1024] = { 0 };
	bool res[256] = { 0 };

	build_masked_tokens_cust(
	  pkM, nullptr, nullptr, rl, port, "127.0.0.1",
	  w, w, nullptr, nullptr, tx, tx, 
	  res, res);
  }

  return 0;
}

/* old main functions (e.g. how to call ecdsa and sha functions) 
 */
int ecdsa_main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

    setup_semi_honest(io, party);

    test_signature();

    delete io;
    return 0;
}

int sha256_main(int argc, char** argv) {
  // generate circuit for use in malicious library
  // this breaks and I don't know why --Marcella
  if (argc == 2 && strcmp(argv[1], "-m") == 0 ) {

    setup_plain_prot(true, "sha256.circuit.txt");
    cout << "set up" << endl;

    uint message[BLOCKS][16] = {0};
    UInteger result[8];
    computeSHA256(message, result);
    for (int i=0; i<8; i++) {
      result[i].reveal<uint>(PUBLIC);
    }

    cout << "finished my stuff" << endl;

    finalize_plain_prot();
     cout << "done" << endl;
    return 0;
  }

  // otherwise, run in semihonest library
  int port, party;
  parse_party_and_port(argv, &party, &port);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  // test_components(party);
  // test_sigmas(party);

  uint message[BLOCKS][16] = {0};

  UInteger result[8];
  computeSHA256(message, result);

  string res = "";
  for (int r=0; r<7; r++){
    res += get_bitstring(result[r]);
  }

  res = change_base(res, 2, 16);
  cout <<"hash: " << res << endl;


  delete io;
  return 0;
}

