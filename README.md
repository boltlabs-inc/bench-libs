This repo is for benchmarking!

Current purpose is to compare two approaches for using MPC techniques. [EMP-toolkit](https://github.com/emp-toolkit) implements traditional 2-party garbled circuit based MPC protocols, including a maliciously secure version that we're itnerested in.
[ZKBoo++]() implements MPC in the head, a zero-knowledge proof technique where the prover reveals transcripts of an MPC computation they executed locally (``in their head''), which the verifier can audit to find signs of cheating.

In both cases, we'll need to compute at least a signature. The `benchmark.py` script tests overall runtime for computing SHA256 hashes and also breaks down each computation into offline (pre-computable) and online timings.

## Docker setup

The Docker image creates an environment to run these tests. It downloads all the dependencies for the two libraries and compiles the SHA256 tests. To run benchmarking, first create a Docker image. 
```
$ docker build -t compare .
```
Spin up a container from the image. 
```
$ docker run -it --rm compare
```
Run the benchmarking script.
```
$ python benchmarking.py
```

You might have to edit the script to get the output you care about.


