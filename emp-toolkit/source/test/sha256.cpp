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

// crypto++ headers
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"
#define byte unsigned char

// boost header to compare strings
#include <boost/algorithm/string.hpp>

string SHA256HashString(string msg);
string run_secure_sha256(string msg);
string test_output(Integer result[8]);

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

// tests compose function (takes 8-block result, squashes into long hash)
// (comparison is to the in-the-clear version I've been using)
// TODO This is broken
void test_compose(int runs=50) {
  // reveal result, parse final hash
  PRG prg;
  unsigned long long range = 1;
  range = range << 32; // doing this in one line raises too-short error

  for(int i = 0; i < runs; ++i) {
    Integer result[8];
    for(int b=0; b < 8; b++) {
      unsigned long long rand;
      prg.random_data(&rand, 8);
      rand %= range;

      result[i] = Integer(32, rand, ALICE);
    //  cout << rand << " " << result[i].reveal<string>() << endl;
    }

    // in the clear
    string res = "";
    for (int r=0; r<8; r++){
      res += get_bitstring(result[r]);
      cout << get_bitstring(result[r])  << endl;
    }

    res = change_base(res, 2, 16);
    while (res.length() < 64) {
      res = '0' + res;
    }
    cout << "expected " << res << endl;

    // secure -- note use of special unsigned reveal function
    Integer hash = composeSHA256result(result);
    string hres = change_base(hash.reveal_unsigned(PUBLIC), 10,16);
    while (hres.length() < 64) {
      hres = '0' + hres;
    }
    cout << "actual" << hres << endl;

    assert ( hres.compare(res) == 0);
  }
}


// this is not actually random for a variety of reasons, but it's ok.
// The worst thing is that rand() produces the same output every time it's compiled
// would be cool to get something that the same for both parties, but different
// per compilation
string gen_random(const int len) {
  static const char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";

  string s = "";
  for (int i = 0; i < len; ++i) {
    s += alphanum[rand() % (sizeof(alphanum) - 1)];
  }
  return s;
}

void test_end_to_end() {
  // known test vector from di-mgt.com.au
  string msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  string expected = SHA256HashString(msg);
  string actual = run_secure_sha256(msg);

  boost::algorithm::to_lower(expected);
  boost::algorithm::to_lower(actual);

  assert ( expected.compare(actual) == 0);
  assert ( expected.compare("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0 );

  // randomized tests of 2-block-length messages
  for (int len=56; len < 119; len++) {
    msg = gen_random(len);
    string expected = SHA256HashString(msg);
    string actual = run_secure_sha256(msg);

    boost::algorithm::to_lower(expected);
    boost::algorithm::to_lower(actual);

    //cout << "test " << len << "\n\t" << expected << "\n\t" << actual << endl;
    assert ( expected.compare(actual) == 0);
  }
}

// reference sha256 implementation by CryptoPP
string SHA256HashString(string msg){
  string digest;
  CryptoPP::SHA256 hash;

  CryptoPP::StringSource foo(msg, true,
      new CryptoPP::HashFilter(hash,
        new CryptoPP::HexEncoder (
          new CryptoPP::StringSink(digest))));

  return digest;
}

// Pad the input to a multiple of 512 bits, and add the length
// in binary to the end.
// This was implemented by Jerry Coffin from StackExchange
string padSHA256(string const &input) {
  static const size_t block_bits = 512;
  uint64_t length = input.size() * 8 + 1;
  size_t remainder = length % block_bits;
  size_t k = (remainder <= 448) ? 448 - remainder : 960 - remainder;
  std::string padding("\x80");
  padding.append(std::string(k/8, '\0'));
  --length;

  for (int i=sizeof(length)-1; i>-1; i--) {
    unsigned char bc = length >> (i*8) & 0xff;
    padding.push_back(bc);
  }
  std::string ret(input+padding);
  return ret;
}

// test sha256 implementation 
string run_secure_sha256(string msg) {
  // pad message using insecure scheme
  string padded_msg = padSHA256(msg);
  string padded_msg_hex;

  // encode message in hex using cryptopp tools
  CryptoPP::StringSource foo(padded_msg, true,
      new CryptoPP::HexEncoder (
        new CryptoPP::StringSink(padded_msg_hex)));

  // parse padded message into blocks
  assert (padded_msg_hex.length() == BLOCKS * 128);
  string blk;
  uint message[BLOCKS][16] = {0};
  for (int b=0; b<BLOCKS; b++) {
    for (int i=0; i<16; i++) {
      blk = padded_msg_hex.substr((b*128) + (i*8), 8);
      message[b][i] = (uint) strtoul(blk.c_str(), NULL,16);
      // cout << "\t" << blk << " --> " << message[b][i] << endl;
    }
  }

  // MPC - run sha256 
  Integer result[8];
  computeSHA256(message, result);

  // convert output to correct-length string
  Integer hash = composeSHA256result(result);
  string res = hash.reveal_unsigned(PUBLIC,16);
  while (res.length() < 64) {
    res = '0' + res;
  }

  return res;
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

  // run unit tests
  test_components(party);
  test_sigmas(party);
  test_compose();

  // run end-to-end tests
  test_end_to_end();





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
