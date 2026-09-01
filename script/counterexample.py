#!/usr/bin/env python3
"""
Demonstrates WHY a byte-free length proof is unsound, justifying the sound
design that sends the (<=1024-byte) final chunk.

Claim under test: "given actual length, the CV of the final chunk, and the
right-edge sibling CVs, the committed root can be reconstructed and the length
proven, WITHOUT the final chunk bytes."

Result: the right-edge fold depends only on (finalChunkCv, rightEdge) and
siblingCount = len(rightEdge). siblingCount is NOT injective in the chunk count
(2, 3, 5, 9, ... chunks all have siblingCount 1), so one file's honest witness
also "verifies" for a different length in the same siblingCount class.
"""
import sys

sys.path.insert(0, "script")
import random

import blake3_tree as b3


def sibling_count(n):
    c = 0
    while n > 1:
        k = 1
        while k * 2 < n:
            k *= 2
        n -= k
        c += 1
    return c


def fold(final_cv_bytes, edge_bytes):
    fw = [int.from_bytes(final_cv_bytes[4 * i:4 * i + 4], "little") for i in range(8)]
    ew = [[int.from_bytes(e[4 * i:4 * i + 4], "little") for i in range(8)] for e in edge_bytes]
    return b3.words_to_bytes(b3.reconstruct_root(fw, ew))


def main():
    # Honest 2-chunk file (1500 bytes). siblingCount(2) == 1.
    A = random.Random(1).randbytes(1500)
    rootA, lenA, fcvA, edgeA = b3.make_length_proof(A)  # byte-free (final CV) proof

    print(f"file A: {lenA} bytes -> {b3.num_chunks(lenA)} chunks, siblingCount={len(edgeA)}")
    print(f"        root = {rootA.hex()}")
    assert fold(fcvA, edgeA) == rootA, "honest reconstruction should match"

    # A DIFFERENT length in a DIFFERENT chunk bucket but the SAME siblingCount.
    forged_len = 2049  # 3 chunks; siblingCount(3) == 1 as well
    print(f"\nforged claim: {forged_len} bytes -> {b3.num_chunks(forged_len)} chunks, "
          f"siblingCount={sibling_count(b3.num_chunks(forged_len))}")

    # The byte-free verifier does the identical fold (edge length still matches
    # siblingCount), so it accepts file A's witness as if the length were 2049.
    accepts = fold(fcvA, edgeA) == rootA and len(edgeA) == sibling_count(b3.num_chunks(forged_len))
    print(f"byte-free verifier accepts len={forged_len} with file A's witness? {accepts}")
    print("=> FALSE POSITIVE: a 1500-byte file 'proves' length 2049. Byte-free length"
          " proofs are UNSOUND.\n")

    print("Fix (implemented in BaoLengthVerifier.sol): send the final chunk's bytes")
    print("(<=1024). The verifier recomputes its CV with counter = N-1, which pins the")
    print("chunk count N; block_len pins the exact byte length. Cost is O(1) calldata.")


if __name__ == "__main__":
    main()
