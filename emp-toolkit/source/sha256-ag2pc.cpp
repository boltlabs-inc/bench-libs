#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"
using namespace std;
using namespace emp;
/*
 * @ayo, @gijs
 *
 * This is an example of the actual runtime interface we'll use
 * for the emp-toolkit maliciously secure library.
 *
 * Required inputs from the library are a party and a port (both ints)
 *
 * Required inputs for MPC can be whatever you define,
 * but they are passed in as one big, squashed bool array
 * (there are questions here of endianness and input order that I 
 *  haven't looked into yet)
 * 
 * To run, you need two parties (1 and 2)
 * Each of them setus up IO (in main, here) and runs the silent_test function
 * which reads a circuit from a file, sets up networking,
 * then runs preprocessing and online phases
 *
 * The last bit checks the result against a hardcoded expected answer.
 *
 */

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

void silent_test(int party, NetIO* io, string name, string check_output = "") {
    // set up
    string file = name;//circuit_file_location + name;
    CircuitFile cf(file.c_str());
    C2PC twopc(io, party, &cf);

    // preprocessing
    twopc.function_independent();
    twopc.function_dependent();

    // initialize inputs (hardcoded 0s here)
    bool *in = new bool[max(cf.n1, cf.n2)];
    bool * out = new bool[cf.n3];
    memset(in, false, max(cf.n1, cf.n2));
    memset(out, false, cf.n3);

    // online -- run computation
    twopc.online(in, out);

    // check result
    if(party == BOB and check_output.size() > 0){
        string res = "";
        for(int i = 0; i < cf.n3; ++i)
            res += (out[i]?"1":"0");
        cout << (res == hex_to_binary(check_output)? "GOOD!":"BAD!")<<endl;
    }

    // clean up
    delete[] in;
    delete[] out;
}

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
	io->set_nodelay();
	silent_test(party, io, circuit_file_location+"sha-256.txt", "da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8");
	delete io;
	return 0;
}
