# Proof-of-Stake Blockchain Demo

A simple demonstration of a Proof of Stake blockchain implementation for a master studies assignment project. This project illustrates the core concepts of a PoS blockchain, including validator selection, block proposal, and consensus mechanisms.

The demo will create a blockchain with several validators (including one "bad actor"), generate 25 blocks, and verify the integrity of the chain.

Any feedback for improvements is welcome!

## Important Notice

**This code is for DEMONSTRATION PURPOSES ONLY and is not suitable for production use.** It is designed to showcase blockchain concepts in a controlled environment and lacks many features required for a real-world blockchain implementation.

## Features

- Proof-of-Stake consensus mechanism
- Validator selection weighted by stake
- Block validation and consensus voting
- Signature verification using ECDSA
- Simulation of "bad actor" validators

## Installation

```bash
uv run main.py
```

## TODO List

- [ ] Implement transaction processing
- [ ] Add block persistence layer
- [ ] Create a simple networking layer
- [ ] Implement validator rewards

