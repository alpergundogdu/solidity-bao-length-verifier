//! Off-chain proof generator for `BaoLengthVerifier.sol`.
//!
//! Reuses the official `blake3` crate's `hazmat` tree API to compute subtree
//! chaining values, so no cryptographic primitive is re-implemented here — this
//! is the reference implementation itself.
//!
//! Configuration: the bao leaf unit == the native BLAKE3 chunk == 1024 bytes,
//! so the bao tree is exactly the BLAKE3 tree.

use blake3::hazmat::{merge_subtrees_non_root, merge_subtrees_root, HasherExt, Mode};
use blake3::Hasher;

pub const CHUNK_LEN: usize = 1024;

pub type Cv = [u8; 32];

/// The sound length proof consumed by the on-chain verifier.
pub struct Proof {
    pub root: [u8; 32],
    pub length: u64,
    /// Final (rightmost) chunk bytes, <= 1024.
    pub final_chunk: Vec<u8>,
    /// Left-sibling subtree CVs along the right spine, TOP -> BOTTOM.
    pub right_edge: Vec<Cv>,
}

/// numChunks = ceil(length/1024), with empty input = 1 chunk.
pub fn num_chunks(length: usize) -> usize {
    if length == 0 {
        1
    } else {
        (length + CHUNK_LEN - 1) / CHUNK_LEN
    }
}

/// Largest power of two strictly less than n (n >= 2).
fn largest_pow2_below(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Chaining value of the left subtree covering chunks `[start, start+count)`.
///
/// Every left sibling on the right spine is a perfect, size-aligned subtree of
/// full chunks, so `finalize_non_root` is valid.
fn subtree_cv(data: &[u8], start_chunk: usize, count: usize) -> Cv {
    let start = start_chunk * CHUNK_LEN;
    let end = core::cmp::min(start + count * CHUNK_LEN, data.len());
    let mut h = Hasher::new();
    h.set_input_offset(start as u64);
    h.update(&data[start..end]);
    h.finalize_non_root()
}

/// Non-root chaining value of the final chunk (chunk index n-1).
fn final_chunk_cv(data: &[u8], n: usize) -> Cv {
    let start = (n - 1) * CHUNK_LEN;
    let mut h = Hasher::new();
    h.set_input_offset(start as u64);
    h.update(&data[start..]);
    h.finalize_non_root()
}

/// Build the sound proof for `data`.
pub fn make_proof(data: &[u8]) -> Proof {
    let len = data.len();
    let n = num_chunks(len);
    let root = *blake3::hash(data).as_bytes();
    let final_start = (n - 1) * CHUNK_LEN;
    let final_chunk = data[final_start..].to_vec();

    // Right edge: peel the largest power of two off the left, descend right.
    let mut right_edge = Vec::new();
    let mut start = 0usize;
    let mut count = n;
    while count > 1 {
        let k = largest_pow2_below(count);
        right_edge.push(subtree_cv(data, start, k));
        start += k;
        count -= k;
    }

    // Self-check: reconstruct the root exactly as the Solidity verifier does.
    if n >= 2 {
        let mut cv = final_chunk_cv(data, n);
        let sc = right_edge.len();
        let mut reconstructed = [0u8; 32];
        for i in (0..sc).rev() {
            if i == 0 {
                reconstructed = *merge_subtrees_root(&right_edge[0], &cv, Mode::Hash).as_bytes();
            } else {
                cv = merge_subtrees_non_root(&right_edge[i], &cv, Mode::Hash);
            }
        }
        assert_eq!(reconstructed, root, "reconstruction must match blake3::hash");
    }

    Proof {
        root,
        length: len as u64,
        final_chunk,
        right_edge,
    }
}

/// Number of right-edge siblings for `n` chunks (mirrors the verifier).
pub fn sibling_count(mut n: usize) -> usize {
    let mut c = 0;
    while n > 1 {
        n -= largest_pow2_below(n);
        c += 1;
    }
    c
}

/// Deterministic filler data (SplitMix64) so runs are reproducible.
pub fn make_data(length: usize, seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; length];
    let mut x = seed.wrapping_add(0x9E3779B97F4A7C15);
    let mut i = 0;
    while i < length {
        let mut z = x;
        x = x.wrapping_add(0x9E3779B97F4A7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        for b in z.to_le_bytes() {
            if i >= length {
                break;
            }
            out[i] = b;
            i += 1;
        }
    }
    out
}
