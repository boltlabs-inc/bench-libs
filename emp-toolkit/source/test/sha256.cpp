/*
 * TODO
 *
 * This will run end-to-end tests on the sha256 functionality
 * and unit tests on the individual components
 * (in build_tokens/sha256.*)
 *
 * 1. generate test vectors (use bristol test vectors, plus some randomized one)
 * 2. import a reference sha256 implementation
 * 3. run tests in clear and under MPC
 * 4. compare results
 *
 */
#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
#include "build_tokens/sha256.h"
using namespace emp;
using namespace std;

void test_sigmas(int party, int range=1<<25, int runs=10) {
  PRG prg;
  for(int i = 0; i < runs; ++i) {
    unsigned long long x;
    prg.random_data(&x, 8);
    x %= range;
    Integer a(BITS,  x, ALICE);

    // make sure both parties have same clear values
    x = a.reveal<uint>(PUBLIC);

    // test sigma functions
    uint result = SIGMA_UPPER_0(a).reveal<uint>(PUBLIC);
    assert ((SIGMA_UPPER_0(x)) == result);

    result = SIGMA_UPPER_1(a).reveal<uint>(PUBLIC);
    assert ((SIGMA_UPPER_1(x)) == result);

    result = SIGMA_LOWER_0(a).reveal<uint>(PUBLIC);
    assert ((SIGMA_LOWER_0(x)) == result);

    result = SIGMA_LOWER_1(a).reveal<uint>(PUBLIC);
    assert ((SIGMA_LOWER_1(x)) == result);
  }
}

void test_components(int party, int range=1<<25, int runs = 10) {
  PRG prg;
  for(int i = 0; i < runs; ++i) {
    unsigned long long x,y,z, n;
    prg.random_data(&x, 8);
    prg.random_data(&y, 8);
    prg.random_data(&z, 8);
    prg.random_data(&n, 8);
    x %= range;
    y %= range;
    z %= range;
    n %= 32;

    Integer a(BITS,  x, ALICE);
    Integer b(BITS,  y, ALICE);
    Integer c(BITS,  z, BOB);
    Integer pn(BITS, n, BOB);

    // make sure both parties have same clear values
    x = a.reveal<uint>(PUBLIC);
    y = b.reveal<uint>(PUBLIC);
    z = c.reveal<uint>(PUBLIC);
    n = pn.reveal<uint>(PUBLIC);

    // test ch
    uint result = CH(a,b,c).reveal<uint>(PUBLIC);
    assert ((CH(x,y,z)) == result);

    // test maj
    result = MAJ(a,b,c).reveal<uint>(PUBLIC);
    assert ((MAJ(x,y,z)) == result);

    // test shr32
    result = SHR32(a, pn).reveal<uint>(PUBLIC);
    assert ((SHR32(x, n)) == result);

    // test rot32
    result = ROR32(a, pn).reveal<uint>(PUBLIC);
    assert (ROR32(x,n) == result);
  }
}

int main(int argc, char** argv) {
  // run in semihonest library
  int port, party;
  parse_party_and_port(argv, &party, &port);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  // run unit tests
  test_components(party);
  test_sigmas(party);

  /*
  uint message[BLOCKS][16] = {0};

  UInteger result[8];
  computeSHA256(message, result);

  string res = "";
  for (int r=0; r<7; r++){
    res += get_bitstring(result[r]);
  }

  res = change_base(res, 2, 16);
  cout <<"hash: " << res << endl;
  */


  delete io;
  return 0;
}
