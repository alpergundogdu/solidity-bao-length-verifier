#!/usr/bin/env python3
"""
Writes human-inspectable test vectors to vectors.json.

Each vector: { length, root, finalChunkHex, rightEdge:[...] } — the exact inputs
to BaoLengthVerifier.verifyBaoLength (finalChunk given as hex). Roots are
cross-checked against the official `blake3` package when available.

Usage:  ./.venv/bin/python script/gen_vectors.py
"""
import json
import random

import blake3_tree as b3

LENGTHS = [
    0, 1, 2, 1023, 1024, 1025, 16383, 16384, 16385, 32767, 32768, 32769,
    65535, 65536, 65537, 100000, 100001, 1048576, 1048577,
    3072, 3073, 5000, 12345, 99999,
]


def main():
    try:
        import blake3
        oracle = True
    except ImportError:
        oracle = False

    out = []
    for L in LENGTHS:
        data = random.Random(L).randbytes(L)
        root, alen, fc, edge = b3.make_sound_proof(data)
        if oracle:
            assert root == blake3.blake3(data).digest(), f"mismatch at {L}"
        out.append({
            "length": alen,
            "numChunks": b3.num_chunks(alen),
            "root": "0x" + root.hex(),
            "finalChunkLen": len(fc),
            "finalChunkHex": "0x" + fc.hex(),
            "rightEdge": ["0x" + cv.hex() for cv in edge],
        })

    with open("vectors.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"wrote vectors.json ({len(out)} vectors, oracle_checked={oracle})")


if __name__ == "__main__":
    main()
