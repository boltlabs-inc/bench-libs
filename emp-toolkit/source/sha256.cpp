#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

#define MERCH ALICE
#define CUST BOB
#define BITS 32

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHR32(x, n) ((x) >> (n))

#define SIGMA_UPPER_0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define SIGMA_UPPER_1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIGMA_LOWER_0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ SHR32(x, 3))
#define SIGMA_LOWER_1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ SHR32(x, 10))

UInteger ROR32(UInteger x, UInteger n) {
  UInteger thirtytwo(BITS, 32, PUBLIC);
  return (x >> n) | (x << (thirtytwo - n));
}
UInteger ROR32(UInteger x, uint n) {
  UInteger shiftamt(BITS, 32 - n, PUBLIC);
  return (x >> n) | (x << shiftamt);
}
uint ROR32(uint x, uint n) {
  return ((x >> n) | (x << (32 - n)));
}

string get_bitstring(UInteger x) {
  string s = "";
  for(int i=0; i<x.size(); i++) {
     s = (x[i].reveal<bool>(PUBLIC) ? "1" : "0") + s;
  }
  return s;
}

void test_sigmas(int party, int range=1<<25, int runs=10) {
  PRG prg;
  for(int i = 0; i < runs; ++i) {
      unsigned long long x;
      prg.random_data(&x, 8);
      x %= range;
      UInteger a(BITS,  x, ALICE);

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

      UInteger a(BITS,  x, ALICE);
      UInteger b(BITS,  y, ALICE);
      UInteger c(BITS,  z, BOB);
      UInteger pn(BITS, n, BOB);

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


void test_sha() {
  UInteger a(32, 5, ALICE);
  UInteger b(32, 10, BOB);

  UInteger c = a + b;
  cout << c.reveal<uint>(PUBLIC) << endl;

  uint x = 234;
  unsigned long long l = 234;

  assert (CH(x,x,x) == CH(l,l,l));
}



int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

    setup_semi_honest(io, party);

    test_sha();
    test_components(party);
    test_sigmas(party);


    delete io;
}
