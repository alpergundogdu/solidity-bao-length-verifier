# Bao / BLAKE3 length verifier (Solidity + Yul)

An EVM verifier that proves the **exact byte length** committed by a BLAKE3/bao
`root`, given the committed root, the claimed length, the **final chunk's bytes
(≤1024)**, and the **right-edge sibling chaining values**. Used to disprove a
signed `(root, claimed_total_bytes)` when `claimed_total_bytes` is false.

> **Configuration.** Here the bao *leaf unit* equals the native BLAKE3 *chunk* =
> **1024 bytes**, so the bao tree is exactly the BLAKE3 tree. (Your first message
> mentioned a 16 KiB bao chunk-group; you then corrected it to 1024. The verifier
> generalizes to 16 KiB groups by treating each group's BLAKE3-subtree CV as a
> leaf — see *Generalizing* below.)

```
src/BaoLengthVerifier.sol      the verifier (Yul BLAKE3 compression) + external harness
prover/                        Rust proof generator (reuses the official blake3 hazmat tree API)
  src/lib.rs                     make_proof(): root, final chunk, right-edge CVs
  src/bin/prove.rs               Foundry FFI oracle (one length)
  src/bin/prove_batch.rs         batch oracle for randomized differential testing
script/blake3_tree.py          independent BLAKE3 tree reference (2nd oracle, hand-derived)
script/counterexample.py       proves the byte-free premise is unsound
script/gen_vectors.py          writes vectors.json for inspection
test/BaoLengthVerifier.t.sol   correctness, adversarial, security, differential
test/GasBench.t.sol            gas benchmarks
```

**Run:**

```bash
cargo build --release --manifest-path prover/Cargo.toml   # build the FFI oracle
forge test -vv
```

The Foundry tests shell out (FFI) to the compiled Rust binaries in
`prover/target/release/`, so the prover must be built first. The Python scripts
are a second, independently written oracle (and host the soundness
counterexample); they are not required to run the test suite.

---

## 1. The premise: proven, then corrected

You asked, before any Solidity, whether this is cryptographically valid:

> given the actual length, the CV of the actual final chunk, and the bao
> right-edge sibling CVs, reconstruct the committed root **without the final
> chunk bytes**.

Splitting your three sub-claims:

| # | Claim | Verdict |
|---|-------|---------|
| 1 | Reconstruct root from a **trusted** final-chunk CV + right edge | ✅ valid |
| 2 | Prove the CV corresponds to the actual bytes | needs the bytes (off-chain in your model) |
| 3 | Prove the **length** against the committed root, **byte-free** | ❌ **invalid** |

**Why #3 fails — derived from the construction.** A BLAKE3 parent node is
`compress(IV, left‖right, counter=0, block_len=64, PARENT)`. Parents commit **no
length, no subtree size, and no counter.** All length information lives in the
*leaves*: each chunk's CV bakes in its absolute **chunk index (the counter)** and
the final block's **`block_len`**. The right-edge fold never touches a leaf's
internals — the siblings are opaque 32-byte CVs.

So the verifier's output depends on exactly three things: `finalChunkCv`, the
`rightEdge` values, and `siblingCount = rightEdge.length` — **not** on
`numChunks` beyond `siblingCount`. And `siblingCount` is badly non-injective:

```
siblingCount = 1  for numChunks ∈ {2, 3, 5, 9, 17, 33, …}   (every 2^k + 1)
siblingCount = 2  for numChunks ∈ {4, 6, 7, 10, 11, 13, …}
```

A malicious prover (who holds the data) can take the **honest witness for the
true tree** and re-present it under **any** false length sharing the same
`siblingCount`. The fold is byte-for-byte identical, so it still equals `root`.

**Minimal counterexample** (`script/counterexample.py`, checked against the
reference):

```
file A = 1500 bytes → 2 chunks, siblingCount 1, root = rootA
byte-free verifier accepts len = 2049 (3 chunks, siblingCount 1) with A's witness → TRUE
```

A 1500-byte file "proves" length 2049. In the slashing setting this lets a
**malicious challenger slash an honest signer**: the signer honestly signs
`(rootA, 1500)`; the challenger submits `actualLength = 2049` with the *real*
2-chunk witness; the contract sees `verify = true` and `2049 ≠ 1500` and wrongly
concludes the signer lied. This is exactly why bao itself **prepends the length**
and verifies it against the actual **chunk bytes** — BLAKE3's root does not
commit the length in any form extractable from the parent tree alone.

## 2. What additional information is necessary

To bind `numChunks = N` you must recompute the **final chunk from its bytes**
with `counter = N-1`. The chunk counter is the missing size-binding datum, and it
is only reachable by recomputing the chunk. Two consequences:

1. **There is no sound "chunk-count-only" middle ground.** The moment you
   recompute the final chunk you also recompute its `block_len`, so you get the
   **exact byte length for free**. If you don't recompute it, you get only
   `siblingCount` (useless).
2. **The requested optimization — never send the final chunk bytes — is
   impossible for a sound length proof.** But the cost is **O(1)**: the final
   chunk is ≤1024 bytes regardless of file size. Off-chaining it would save at
   most ~1 KB and cannot be done soundly.

This is the honest answer to your deliverable #8/#9: the final-chunk CV **must**
be authenticated against the underlying bytes, and the only way to do that
on-chain is to supply those ≤1024 bytes.

## 3. The sound verifier

```solidity
function verifyBaoLength(
    bytes32 root,
    uint64 actualLength,
    bytes calldata finalChunk,     // the final (rightmost) chunk, ≤1024 bytes
    bytes32[] calldata rightEdge   // left-sibling subtree CVs, TOP → BOTTOM
) external pure returns (bool);
```

Algorithm:

1. `n = numChunks(actualLength) = max(1, ceil(actualLength/1024))`.
2. **Exact-length binding:** require
   `finalChunk.length == actualLength - (n-1)*1024`. (Lying about `actualLength`
   either changes `n` — hence the counter/geometry and the root — or fails this
   check.)
3. Recompute `finalChunkCv = chunkCV(finalChunk, counter = n-1)` by chaining up
   to 16 BLAKE3 block compressions with `CHUNK_START` / `CHUNK_END` flags and the
   real per-block `block_len`. (For `n == 1`, apply `ROOT` here — the root *is*
   the single chunk's ROOT output; `rightEdge` must be empty.)
4. Fold up the right spine: for `i = sc-1 … 0`,
   `cv = compress(IV, rightEdge[i] ‖ cv, 0, 64, PARENT | (i==0 ? ROOT : 0))`.
5. Return `cv == root`.

### Proof format (smallest practical)

`(uint64 actualLength, bytes finalChunk[≤1024], bytes32[] rightEdge)` plus the
committed `root`. The only "metadata strictly required by the spec" is the final
chunk's byte length (implicit in `finalChunk.length`) and the tree geometry —
both **derived from `actualLength`**, not sent separately. `rightEdge` length is
`siblingCount(n) ≤ ceil(log2 n) ≤ 54` for any `uint64` length.

Order of `rightEdge`: **top → bottom**. Index 0 is the topmost/largest left
subtree (combined last, with `ROOT`); the last element is the sibling of the
final chunk. Derived directly from BLAKE3's split rule ("left subtree = largest
power of two number of chunks strictly less than the total").

## 4. Why the proof is sufficient (no hand-waving)

The verifier recomputes, from first principles, the entire right spine of the
BLAKE3 tree of `n = numChunks(actualLength)` chunks:

- The **final chunk CV** is recomputed from the supplied bytes with
  `counter = n-1`. By BLAKE3's collision resistance, only the true final chunk at
  index `n-1` yields a CV that folds to `root`. This pins `n` (via the counter)
  **and** the exact final-chunk byte length (via `block_len`).
- Each **parent compression** is exactly BLAKE3's `PARENT` node; the topmost adds
  `ROOT`, matching how BLAKE3 finalizes.
- `finalChunk.length` is checked against `actualLength`, so `actualLength` is
  bound to the exact byte count, not merely the chunk count.

Hence `verify(root, L, finalChunk, rightEdge) = true` implies `L` is *the* length
of the data behind `root` (up to a BLAKE3 collision). To disprove a signed
`claimed`, present the true `(actualLength, finalChunk, rightEdge)`; if it
verifies and `actualLength ≠ claimed`, the claim is false — and, unlike the
byte-free scheme, a malicious challenger cannot manufacture a passing proof for a
false length (doing so requires a BLAKE3 second preimage / collision).

## 5. Edge cases handled

Empty (0), single partial chunk (1, 1023), exactly one chunk (1024), one over a
boundary (1025), power-of-two chunk counts, non-powers, partial vs full final
chunk — all covered in `test_MandatoryLengths` and the differential tests. The
empty input is anchored by a **non-FFI known-answer test** against the official
BLAKE3 empty hash `af1349b9…`, which validates `IV`, chunk compression, the
`CHUNK_START|CHUNK_END|ROOT` path, and little-endian serialization.

## 6. Security tests (the important ones)

- `test_Security_SameWitness_OnlyTrueLengthVerifies`: with a fixed
  `(finalChunk, rightEdge)`, the verifier accepts the **true length only** — it
  rejects both (a) a different chunk count with the same `siblingCount` (the byte-
  free counterexample: 2 chunks ≠ 3 chunks) and (b) the same chunk count off by
  one byte.
- `test_Security_WindowSweep`: sweeps every claimed length in `[trueLen±40]`;
  only the exact true length verifies.
- **Two different lengths with the same tree shape?** Yes — every length in
  `((k-1)·1024, k·1024]` shares the chunk count `k` and thus the tree shape. What
  disambiguates them is the final chunk's `block_len`, which the verifier
  recomputes from the supplied final-chunk bytes. That is precisely the
  information the byte-free scheme lacked.

## 7. Differential testing

- `test_Differential_Batch`: 400 random lengths in `[0, 40000]` proven by the
  Rust generator and verified on-chain; each also rejected at `length ± 1`.
- `testFuzz_Differential`: fuzzed lengths in `[0, 200000]`.
- The Rust generator computes subtree CVs with the **official `blake3` crate's
  `hazmat` tree API** and self-checks that its right edge reconstructs
  `blake3::hash(data)`. So the chain of trust is **official blake3 (hazmat) →
  Solidity**. The Python `blake3_tree.py` is a second, independently derived
  reference (cross-checked against the `blake3` package) for defense in depth.

## 8. Gas (from `test/GasBench.t.sol`)

Per BLAKE3 block compression ≈ **39k gas**. Compressions per proof =
`ceil(finalChunkLen/64) + siblingCount` (≤ 16 + 54).

| Case | chunks | siblings | compressions | calldata (B) | total verify gas |
|------|-------:|---------:|-------------:|-------------:|-----------------:|
| 1 chunk | 1 | 0 | 16 | 1220 | 634,598 |
| 2 chunks | 2 | 1 | 17 | 1252 | 669,346 |
| 4 chunks | 4 | 2 | 18 | 1284 | 708,529 |
| 8 chunks | 8 | 3 | 19 | 1316 | 747,735 |
| 16 chunks | 16 | 4 | 20 | 1348 | 786,995 |
| 1 MiB (2²⁰ B, 1024 chunks) | 1024 | 10 | 26 | 1540 | 1,023,492 |
| 1 GiB depth (synthetic) | 2²⁰ | 20 | 36 | 1860 | 1,425,963 |

Isolation: **calldata** ≈ 17–27k intrinsic gas (dominated by the ≤1024-byte final
chunk); **compression** ≈ 39k × compressions; **traversal** = `siblingCount`
parent compressions; **total** as measured. The 16-block final-chunk hash
dominates small proofs; depth adds only ~39k/level. The synthetic 1 GiB case uses
real geometry with arbitrary CVs (no gigabytes materialized).

## 9. Caveats

- **The final-chunk CV must be authenticated against the bytes; that is why the
  ≤1024 final-chunk bytes are mandatory, not optional.** A byte-free proof is
  unsound (§1).
- The proof reveals the final chunk's contents (≤1024 bytes). If that tail is
  sensitive, this scheme is unsuitable; there is no sound zero-knowledge-of-the-
  tail variant without a SNARK over the final-chunk hash.
- `root` is the plain BLAKE3 hash. Bao's outboard file additionally prepends an
  8-byte little-endian length; that framing is **not** covered by `root` and is
  irrelevant here — the signature commits the length, and this verifier disproves
  it against `root`.
- Assumes BLAKE3 unkeyed hashing. Keyed / derive-key modes change the leaf IV and
  flags and are out of scope.

### Generalizing to 16 KiB bao chunk-groups

If a deployment uses 16 KiB groups (16 native chunks per leaf), the outboard
tree's leaves are group-CVs = BLAKE3 subtree hashes over 16 chunks. The verifier
is unchanged **except** `_chunkCV` becomes "hash the final *group*": recompute the
final group's BLAKE3 subtree (up to 16 chunk leaves, each with its own counter)
from the final group's bytes (≤16 KiB), then fold the group-level right edge. The
counter/`block_len` binding argument is identical, one level down.
