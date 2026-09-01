"""
Minimal, auditable BLAKE3 tree reference used as ground truth for the
BaoLengthVerifier proof-of-concept.

It implements exactly the pieces of BLAKE3 that the on-chain verifier relies on:

  * chunk hashing (leaves)          -> chunk chaining values (CVs)
  * parent-node compression         -> interior CVs and the ROOT output
  * the BLAKE3 tree geometry rule    ("left subtree = largest power of two
                                       number of chunks strictly less than total")

The whole module is cross-checked against the official `blake3` package
(the Rust binding) in `selftest()` for thousands of random inputs, so the
constants and wiring are validated end-to-end, not just by inspection.

Terminology note (per the task): here the *bao leaf unit* == the *native
BLAKE3 chunk* == 1024 bytes. There is no 16 KiB chunk-group indirection in
this configuration, so the bao tree is exactly the BLAKE3 tree.

References:
  BLAKE3 reference_impl.rs  (constants verified verbatim, 2026-09):
    IV, MSG_PERMUTATION, flags, BLOCK_LEN=64, CHUNK_LEN=1024,
    g() rotations 16/12/8/7, parent: counter=0 / block_len=64 / PARENT flag,
    output CV = first 8 words, state[i] ^= state[i+8].
"""

MASK = 0xFFFFFFFF

IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3

BLOCK_LEN = 64
CHUNK_LEN = 1024


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & MASK
    s[d] = rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK
    s[b] = rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & MASK
    s[d] = rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK
    s[b] = rotr(s[b] ^ s[c], 7)


def round_fn(s, m):
    # columns
    g(s, 0, 4, 8, 12, m[0], m[1])
    g(s, 1, 5, 9, 13, m[2], m[3])
    g(s, 2, 6, 10, 14, m[4], m[5])
    g(s, 3, 7, 11, 15, m[6], m[7])
    # diagonals
    g(s, 0, 5, 10, 15, m[8], m[9])
    g(s, 1, 6, 11, 12, m[10], m[11])
    g(s, 2, 7, 8, 13, m[12], m[13])
    g(s, 3, 4, 9, 14, m[14], m[15])


def compress(cv, block_words, counter, block_len, flags):
    """Return the 8-word (first_8_words) chaining value / root output."""
    s = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter & MASK, (counter >> 32) & MASK, block_len & MASK, flags & MASK,
    ]
    m = list(block_words)
    for r in range(7):
        round_fn(s, m)
        if r < 6:
            m = [m[MSG_PERMUTATION[i]] for i in range(16)]
    return [(s[i] ^ s[i + 8]) & MASK for i in range(8)]


def words_from_block(block):
    """64-byte block -> 16 little-endian 32-bit words (zero padded)."""
    b = block + b"\x00" * (BLOCK_LEN - len(block))
    return [int.from_bytes(b[4 * i:4 * i + 4], "little") for i in range(16)]


def words_to_bytes(words):
    return b"".join(w.to_bytes(4, "little") for w in words)


# ---------------------------------------------------------------------------
# Chunk hashing (leaves)
# ---------------------------------------------------------------------------

def chunk_cv(chunk, counter, root):
    """Chaining value of a single chunk (<= 1024 bytes).

    `counter` is the chunk index. `root` applies the ROOT flag to the final
    block (only ever true when the whole input is exactly one chunk).
    """
    assert 0 <= len(chunk) <= CHUNK_LEN
    # At least one block, even for an empty chunk.
    if len(chunk) == 0:
        blocks = [b""]
    else:
        blocks = [chunk[i:i + BLOCK_LEN] for i in range(0, len(chunk), BLOCK_LEN)]
    cv = list(IV)
    n = len(blocks)
    for i, block in enumerate(blocks):
        flags = 0
        if i == 0:
            flags |= CHUNK_START
        if i == n - 1:
            flags |= CHUNK_END
            if root:
                flags |= ROOT
        cv = compress(cv, words_from_block(block), counter, len(block), flags)
    return cv


# ---------------------------------------------------------------------------
# Parent nodes
# ---------------------------------------------------------------------------

def parent_cv(left, right, root):
    """Parent compression of two 8-word child CVs. counter=0, block_len=64."""
    msg = list(left) + list(right)
    flags = PARENT | (ROOT if root else 0)
    return compress(list(IV), msg, 0, BLOCK_LEN, flags)


# ---------------------------------------------------------------------------
# Tree geometry
# ---------------------------------------------------------------------------

def num_chunks(length):
    if length == 0:
        return 1  # a single empty chunk
    return (length + CHUNK_LEN - 1) // CHUNK_LEN


def largest_power_of_two_below(n):
    """Largest power of two strictly less than n (n >= 2)."""
    assert n >= 2
    p = 1
    while p * 2 < n:
        p *= 2
    return p


def chunks_of(data):
    if len(data) == 0:
        return [b""]
    return [data[i:i + CHUNK_LEN] for i in range(0, len(data), CHUNK_LEN)]


def subtree_cv(chunks, start, count):
    """Non-root CV of the subtree covering chunks [start, start+count)."""
    if count == 1:
        return chunk_cv(chunks[start], start, root=False)
    k = largest_power_of_two_below(count)
    left = subtree_cv(chunks, start, k)
    right = subtree_cv(chunks, start + k, count - k)
    return parent_cv(left, right, root=False)


def right_edge_cvs(chunks, n):
    """Left-sibling subtree CVs along the right spine, TOP -> BOTTOM order.

    Reconstruction consumes these from the bottom (last) up to the top (first),
    applying ROOT at the topmost (index 0) parent compression.
    """
    sibs = []
    start = 0
    count = n
    while count > 1:
        k = largest_power_of_two_below(count)
        sibs.append(subtree_cv(chunks, start, k))  # left subtree
        start += k
        count -= k
    return sibs


def final_chunk_cv(chunks, n):
    return chunk_cv(chunks[n - 1], n - 1, root=False)


def reconstruct_root(final_cv, right_edge):
    """EXACTLY mirrors the Solidity verifier: fold bottom-up, ROOT at top."""
    cv = list(final_cv)
    for i in range(len(right_edge) - 1, -1, -1):
        cv = parent_cv(right_edge[i], cv, root=(i == 0))
    return cv


def bao_root(data):
    """Full BLAKE3/bao root of `data` (32 bytes)."""
    chunks = chunks_of(data)
    n = len(chunks)
    if n == 1:
        return words_to_bytes(chunk_cv(chunks[0], 0, root=True))
    fcv = final_chunk_cv(chunks, n)
    edge = right_edge_cvs(chunks, n)
    return words_to_bytes(reconstruct_root(fcv, edge))


# ---------------------------------------------------------------------------
# Proof object
# ---------------------------------------------------------------------------

def make_length_proof(data):
    """DEPRECATED byte-free proof: (root, length, final_chunk_cv, right_edge).

    Kept only to reproduce the soundness counterexample; NOT sound for length
    verification (binds siblingCount, not chunk count). Use make_sound_proof.
    """
    chunks = chunks_of(data)
    n = len(chunks)
    root = bao_root(data)
    if n == 1:
        fcv = words_to_bytes(chunk_cv(chunks[0], 0, root=False))
        return root, len(data), fcv, []
    fcv = words_to_bytes(final_chunk_cv(chunks, n))
    edge = [words_to_bytes(cv) for cv in right_edge_cvs(chunks, n)]
    return root, len(data), fcv, edge


def make_sound_proof(data):
    """Return (root32, actual_length, final_chunk_bytes, right_edge[list of 32]).

    This is the SOUND proof consumed by the on-chain verifier: the final chunk's
    bytes (<=1024) let the verifier recompute its CV with counter = N-1, binding
    the exact length. Handles all sizes including empty and single-chunk.
    """
    chunks = chunks_of(data)
    n = len(chunks)
    root = bao_root(data)
    final_bytes = chunks[n - 1]  # b"" for empty input
    if n == 1:
        return root, len(data), final_bytes, []
    edge = [words_to_bytes(cv) for cv in right_edge_cvs(chunks, n)]
    return root, len(data), final_bytes, edge


def selftest(trials=2000, seed=1234):
    """Cross-check bao_root() against the official `blake3` package."""
    import random
    import blake3  # official Rust binding

    rng = random.Random(seed)
    # deterministic edge lengths + random lengths
    lengths = [0, 1, 2, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 2049,
               3072, 4096, 5000, 8192, 16384, 100000]
    for _ in range(trials):
        lengths.append(rng.randint(0, 300000))
    ok = 0
    for L in lengths:
        data = bytes(rng.randint(0, 255) for _ in range(L)) if L <= 4096 \
            else bytes((i * 2654435761) & 0xFF for i in range(L))
        mine = bao_root(data)
        want = blake3.blake3(data).digest()
        assert mine == want, f"MISMATCH at len={L}: {mine.hex()} != {want.hex()}"
        # also verify reconstruct_root matches for n>=2
        if num_chunks(L) >= 2:
            r, _, fcv, edge = make_length_proof(data)
            fcvw = [int.from_bytes(fcv[4 * i:4 * i + 4], "little") for i in range(8)]
            edgew = [[int.from_bytes(e[4 * i:4 * i + 4], "little") for i in range(8)] for e in edge]
            assert words_to_bytes(reconstruct_root(fcvw, edgew)) == r
        ok += 1
    print(f"selftest OK: {ok} inputs match official blake3 package")


if __name__ == "__main__":
    selftest()
