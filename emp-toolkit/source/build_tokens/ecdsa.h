#pragma once
#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;
using namespace std;

#define MERCH ALICE
#define CUST BOB

const int QLEN = 256;

struct ECDSA_sig {
  Integer rx;
  Integer ry;
  Integer s;
};

// computes SHA256 hash of the input
// todo; maybe require this in a different format 
// (e.g. padded and in blocks)
Integer signature_hash(Integer m);

// hard-coded conversion of secp256k1 point order 
// (e.g. modulus)
// you can go check that these have the same value
void get_ECDSA_params(string *q); 

// ecdsa-signs a message based on the given parameters
// parameters here are appended -c because they're in the clear
// q : subgroup order
// rx, ry : public key point on curve
// sk : private key integer
// ki : private key
struct ECDSA_sig ecdsa_sign(int skc, int kic,
                     int mc);


// small test function; expected result 2
void test_signature();


