#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

#define F(x,y,z) ((x)^(y)^(z))
#define G(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define H(x,y,z) (((x) | ~(y)) ^ (z))
#define I(x,y,z) (((x)&(z)) | ((y) & ~(z)))
#define J(x,y,z) ((x)^((y) | ~(z)))

int rev(Integer x) {
  return x.reveal<int>(PUBLIC);
}

/* ROL(x, n) cyclically rotates x over n bits to the left */
/* x must be of an unsigned 32 bits type and 0 <= n < 32. */
Integer inline ROL(Integer x, Integer n) {
  Integer rollover = Integer(32, 32, PUBLIC) - n;
  return (( x << n ) | ( x >> rollover )); 
}

Integer inline ROL(Integer x, int n) {
  return (( x << n ) | ( x >> (32 - n))); 
}

void test_basic_functions(int range = 1<<25) {
  PRG prg(fix_key);
  long long x,y,z;
  prg.random_data(&x, 8);
  prg.random_data(&y, 8);
  prg.random_data(&z, 8);
  x %= range;
  y %= range;
  z %= range;

  Integer a(32, x, ALICE);
  Integer b(32, y, BOB);
  Integer c(32, z, BOB);

  assert ((F(x,y,z)) == (F(a,b,c).reveal<int>(PUBLIC)));
  assert ((G(x,y,z)) == (G(a,b,c).reveal<int>(PUBLIC)));
  assert ((H(x,y,z)) == (H(a,b,c).reveal<int>(PUBLIC)));
  assert ((I(x,y,z)) == (I(a,b,c).reveal<int>(PUBLIC)));
  assert ((J(x,y,z)) == (J(a,b,c).reveal<int>(PUBLIC)));
}

#define testROL(x,n)    (((x) << (n)) | ((x) >> (32-(n))))
void test_rollover(int range = 1<<31) {
  PRG prg(fix_key);
  long long x,y,z,w;
  prg.random_data(&x, 8);
  prg.random_data(&y, 8);
  prg.random_data(&z, 8);
  x %= range;
  y %= range;
  z %= range;

  Integer a(32, x, ALICE);
  Integer b(32, y, BOB);
  Integer c(32, z, BOB);

  // test public/private versions are equal
  for(int n=0; n<32; n++) {
    Integer nI(32, n, PUBLIC);
    assert (ROL(a, n).reveal<int>(PUBLIC) == ROL(a, nI).reveal<int>(PUBLIC));
    assert (ROL(b, n).reveal<int>(PUBLIC) == ROL(b, nI).reveal<int>(PUBLIC));
    assert (ROL(c, n).reveal<int>(PUBLIC) == ROL(c, nI).reveal<int>(PUBLIC));
  }

  // test behavior compared to reference impl
  // TODO this fails at n=2
  prg.random_data(&w, 8);
  w %= range;
  Integer d(32, w, ALICE);
  for(int n=0; n<32; n++) {
    assert( testROL(w,n) == ROL(d,n).reveal<int>(PUBLIC) );
  }
}

// the ten basic operations
#define FF(a, b, c, d, e, x, s) {\
  (a) += F((b), (c), (d)) + (x);\
  (a) = ROL((a), (s)) + (e);\
  (c) = ROL((c), 10);\
  }


void test_basic_operations(int range = 1<<31, int runs=10) {
  return;
}

template<typename Op, typename Op2>
void test_int(int party, int range1 = 1<<25, int range2 = 1<<25, int runs = 100) {
	PRG prg(fix_key);
	for(int i = 0; i < runs; ++i) {
		long long ia, ib;
		prg.random_data(&ia, 8);
		prg.random_data(&ib, 8);
		ia %= range1;
		ib %= range2;
		while( Op()(int(ia), int(ib)) != Op()(ia, ib) ) {
			prg.random_data(&ia, 8);
			prg.random_data(&ib, 8);
			ia %= range1;
			ib %= range2;
		}
	
		Integer a(32, ia, ALICE); 
		Integer b(32, ib, BOB);

		Integer res = Op2()(a,b);

		if (res.reveal<int>(PUBLIC) != Op()(ia,ib)) {
			cout << ia <<"\t"<<ib<<"\t"<<Op()(ia,ib)<<"\t"<<res.reveal<int>(PUBLIC)<<endl<<flush;
		}
		assert(res.reveal<int>(PUBLIC) == Op()(ia,ib));
	}
	cout << typeid(Op2).name()<<"\t\t\tDONE"<<endl;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

	setup_semi_honest(io, party);


//	scratch_pad();return 0;
    for (int i=0; i<1; i++) {
      test_basic_functions();
      test_rollover();
    }
    /*
    test_int<std::plus<int>, std::plus<Integer>>(party);
	test_int<std::minus<int>, std::minus<Integer>>(party);
	test_int<std::multiplies<int>, std::multiplies<Integer>>(party);
	test_int<std::divides<int>, std::divides<Integer>>(party);
	test_int<std::modulus<int>, std::modulus<Integer>>(party);

	test_int<std::bit_and<int>, std::bit_and<Integer>>(party);
	test_int<std::bit_or<int>, std::bit_or<Integer>>(party);
	test_int<std::bit_xor<int>, std::bit_xor<Integer>>(party);
    */

	delete io;
}
