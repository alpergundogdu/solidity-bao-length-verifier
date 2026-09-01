#!/usr/bin/env python3
"""
Batch proof oracle for randomized differential testing.

Usage:
    prove_batch.py <count> <seed> [maxlen]

Generates `count` random lengths in [0, maxlen], builds a sound proof for each
(cross-checked against the official `blake3` package when available), and prints
the ABI-encoding of parallel arrays:

    (uint64[] lengths, bytes32[] roots, bytes[] finalChunks, bytes32[][] edges)

as a single 0x-hex string. Amortizes interpreter startup across many vectors.
"""
import random
import sys

from eth_abi import encode

import blake3_tree as b3


def main():
    count = int(sys.argv[1])
    seed = int(sys.argv[2])
    maxlen = int(sys.argv[3]) if len(sys.argv) > 3 else 70000

    rng = random.Random(seed)
    try:
        import blake3
        have_oracle = True
    except ImportError:
        have_oracle = False

    lengths, roots, finals, edges = [], [], [], []
    for _ in range(count):
        L = rng.randint(0, maxlen)
        data = rng.randbytes(L)
        root, alen, fc, edge = b3.make_sound_proof(data)
        if have_oracle:
            assert root == blake3.blake3(data).digest()
        lengths.append(alen)
        roots.append(root)
        finals.append(fc)
        edges.append(edge)

    enc = encode(
        ["uint64[]", "bytes32[]", "bytes[]", "bytes32[][]"],
        [lengths, roots, finals, edges],
    )
    sys.stdout.write("0x" + enc.hex())


if __name__ == "__main__":
    main()
