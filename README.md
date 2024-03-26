This repository contains a fork of [risc0](https://github.com/risc0/risc0)'s
[zkevm example](https://github.com/risc0/risc0/tree/3acdb0c292d67cf77028f54c7dd53cdf75ed66f7/examples/zkevm-demo)
ported to run on [PolkaVM](https://github.com/koute/polkavm).

It replays a given Ethereum transaction (by default it uses [0x600d18676aef439ec6ba33d143b78878a520682be7fd8331c74bdf672988a2b1](https://etherscan.io/tx/0x600d18676aef439ec6ba33d143b78878a520682be7fd8331c74bdf672988a2b1), taken from [this blog post](https://www.risczero.com/blog/continuations))
using an EVM interpreter under both risc0 and PolkaVM and prints out the relevant timings.

## Benchmark results

Hardware: Threadripper 3970x 32-core CPU, GeForce RTX 4090

- PolkaVM compilation time: 7.47ms
- PolkaVM execution time: 2.96ms
- PolkaVM total time: 10.43ms
- risc0 execution time: 719.1ms
- risc0 proof generation time: 610.2s
- risc0 proof verification time: 213ms
- Peak VRAM usage during proof generation: ~20GB (manually monitored using `nvidia-smi`)
- risc0 number of segments: 12
- risc0 total cycles: 12058624
- risc0 user cycles: 10301180

A few notes:

- The "PolkaVM compilation time" is the time it takes to recompile the EVM interpreter into the native code. Normally it'd only have to be done once, and then can be reused for multiple transactions.
- The "PolkaVM execution time" is the time it takes to replay the transaction.
- The "risc0 execution time" is the time reported by risc0's executor in its logs, and is used as part of proof generation to first split the computation into segments.
- The "risc0 proof generation time" is measured by the benchmark and is the total time required to generate the proof.
- The "risc0 verification time" is measured by the benchmark and is the time required to verify the proof.
- The number of segments and the number of cycles were taken from risc0's logs.
- This was ran on a single machine, however risc0's proof generation can be further be parallelized on multiple machines, up to the number of segments.
- See the "How long does it take to generate a proof?" section from [this blog post](https://www.risczero.com/blog/zeth-release) for more details on how the proof generation under risc0 works.

## Reproduction

```
$ ./01-install-polkavm-toolchain.sh
$ ./01-install-risc0-toolchain.sh
$ ./02-build-polkavm-guest-program.sh
RUST_LOG=risc0_zkvm=info cargo run --release --features cuda
```

Only Linux is supported.
