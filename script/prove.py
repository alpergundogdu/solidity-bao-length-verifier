#!/usr/bin/env python3
"""
Off-chain proof generator, also used as the Foundry FFI oracle.

Usage:
    prove.py <length> [seed]

Builds deterministic data of `length` bytes (seeded), computes the SOUND bao
length proof via the audited reference in blake3_tree.py, cross-checks the root
against the official `blake3` package when available, and prints the
ABI-encoding of:

    (bytes32 root, uint64 actualLength, bytes finalChunk, bytes32[] rightEdge)

as a single 0x-hex string on stdout (the format Foundry's vm.ffi expects).
"""
import random
import sys

import blake3_tree as b3


def make_data(length: int, seed: int) -> bytes:
    return random.Random(seed).randbytes(length)


def _word(x: int) -> bytes:
    return x.to_bytes(32, "big")


def abi_encode_proof(root: bytes, length: int, final_chunk: bytes, edge: list) -> bytes:
    assert len(root) == 32
    # tuple(bytes32, uint64, bytes, bytes32[]) -> two dynamic tails (bytes, bytes32[])
    head = b""
    head += root                 # w0: bytes32
    head += _word(length)        # w1: uint64
    off_bytes = 4 * 32           # w2 filled below
    # bytes tail: length + padded data
    pad = (-len(final_chunk)) % 32
    bytes_tail = _word(len(final_chunk)) + final_chunk + b"\x00" * pad
    off_edge = off_bytes + len(bytes_tail)
    head += _word(off_bytes)     # w2: offset to finalChunk
    head += _word(off_edge)      # w3: offset to rightEdge
    edge_tail = _word(len(edge))
    for cv in edge:
        assert len(cv) == 32
        edge_tail += cv
    return head + bytes_tail + edge_tail


def main():
    length = int(sys.argv[1])
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    data = make_data(length, seed)

    root, actual_length, final_chunk, edge = b3.make_sound_proof(data)

    try:
        import blake3
        assert root == blake3.blake3(data).digest(), "root mismatch vs official blake3"
    except ImportError:
        pass

    enc = abi_encode_proof(root, actual_length, final_chunk, edge)
    sys.stdout.write("0x" + enc.hex())


if __name__ == "__main__":
    main()
