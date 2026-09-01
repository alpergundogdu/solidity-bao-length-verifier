// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BaoLengthVerifier (sound variant)
/// @notice Proves the EXACT byte length behind a committed BLAKE3/bao `root`,
///         given the committed root, the claimed length, the FINAL chunk's
///         bytes (<= 1024), and the right-edge sibling chaining values.
///
/// @dev Configuration: the bao *leaf unit* == the native BLAKE3 *chunk* = 1024
///      bytes, so the bao tree is exactly the BLAKE3 tree.
///
///      WHY THE FINAL CHUNK BYTES ARE REQUIRED (not optional):
///      BLAKE3 parent nodes commit no length, no subtree size, and no counter
///      (parent = compress(IV, left||right, counter=0, block_len=64, PARENT)).
///      All length information lives in the *leaves*: each chunk's CV bakes in
///      its absolute chunk index (the `counter`) and the final block's
///      `block_len`. A right-edge-only "proof" therefore binds only the number
///      of siblings (siblingCount), which is NOT injective in the chunk count
///      (e.g. 2, 3, 5, 9, ... chunks all have siblingCount 1) -- so it cannot
///      soundly prove the length. Recomputing the final chunk from its bytes
///      with counter = N-1 pins N (and, via block_len, the exact byte length).
///      The final chunk is <= 1024 bytes regardless of file size, so this costs
///      O(1) calldata.
///
///      Every leaf compression chains up to 16 blocks with counter = N-1; every
///      parent compression uses counter = 0, block_len = 64, PARENT (| ROOT at
///      the top). Single-chunk inputs (length 0..1024) are handled directly:
///      the root is the chunk's ROOT-flagged output.
library BaoLengthVerifier {
    uint256 internal constant CHUNK_LEN = 1024;
    uint256 internal constant BLOCK_LEN = 64;

    // BLAKE3 domain-separation flags.
    uint256 internal constant CHUNK_START = 1;
    uint256 internal constant CHUNK_END = 2;
    uint256 internal constant PARENT = 4;
    uint256 internal constant ROOT = 8;

    // BLAKE3 IV serialised as a chaining value (8 little-endian 32-bit words).
    bytes32 internal constant IV_BYTES = 0x67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b;

    /// @notice Verify that `root` is the BLAKE3/bao root of exactly
    ///         `actualLength` bytes whose final chunk is `finalChunk`.
    /// @param root         Committed BLAKE3/bao root (32 bytes, BLAKE3 digest order).
    /// @param actualLength Claimed exact total byte length.
    /// @param finalChunk   The final (rightmost) chunk's bytes. Length must equal
    ///                     `actualLength - (numChunks-1)*1024` (in 0..1024).
    /// @param rightEdge    Left-sibling subtree CVs along the right spine, TOP ->
    ///                     BOTTOM (index 0 = topmost/largest left subtree; last =
    ///                     sibling of the final chunk). Empty for single-chunk input.
    /// @return ok          True iff reconstruction matches `root`.
    function verifyBaoLength(
        bytes32 root,
        uint64 actualLength,
        bytes calldata finalChunk,
        bytes32[] calldata rightEdge
    ) internal pure returns (bool ok) {
        uint256 n = numChunks(actualLength);

        // Exact-length binding: the final chunk's byte count is fixed by
        // actualLength and n. If a caller lies about actualLength, either n
        // changes (counter/geometry change -> different root) or this check fails.
        uint256 expectedFinalLen;
        unchecked {
            expectedFinalLen = uint256(actualLength) - (n - 1) * CHUNK_LEN;
        }
        if (finalChunk.length != expectedFinalLen) return false;
        if (finalChunk.length > CHUNK_LEN) return false;

        if (n == 1) {
            // Root IS the chunk's ROOT-flagged output; no parents.
            if (rightEdge.length != 0) return false;
            return _chunkCV(finalChunk, 0, true) == root;
        }

        uint256 sc = siblingCount(n);
        if (rightEdge.length != sc) return false;

        // Final chunk CV with counter = n-1 (this pins n), non-root.
        bytes32 cv = _chunkCV(finalChunk, n - 1, false);

        // Fold bottom-up; ROOT flag at the topmost parent (index 0).
        for (uint256 i = sc; i > 0; ) {
            unchecked {
                --i;
            }
            uint256 flags = (i == 0) ? (PARENT | ROOT) : PARENT;
            cv = _compressBlock(IV_BYTES, rightEdge[i], cv, 0, BLOCK_LEN, flags);
        }
        return cv == root;
    }

    /// @notice Overclaim fraud predicate. Proves that a signed `claimedLength`
    ///         is an OVERCLAIM, i.e. the true length is strictly smaller.
    ///
    /// @dev We only act on overclaims (`claimedLength > actualLength`). Truthful
    ///      claims and underclaims (`claimedLength <= actualLength`) "pass":
    ///      the function returns false without requiring a valid witness, since
    ///      they are out of scope here.
    ///
    ///      Soundness note: the true-length binding lives entirely in
    ///      verifyBaoLength (the final chunk is recomputed with counter = N-1).
    ///      A malicious challenger therefore cannot frame an honest signer by
    ///      claiming a smaller `actualLength` than the real one -- that would
    ///      require a valid witness for a length the root does not commit to,
    ///      i.e. a BLAKE3 collision.
    ///
    /// @param root          Committed BLAKE3/bao root.
    /// @param claimedLength The signed / asserted length being challenged.
    /// @param actualLength  The true length, established by the witness below.
    /// @param finalChunk    Final chunk bytes for `actualLength` (<= 1024).
    /// @param rightEdge     Right-edge sibling CVs for `actualLength`.
    /// @return overclaimProven True iff `claimedLength > actualLength` AND the
    ///         witness proves the true length is `actualLength`.
    function proveOverclaim(
        bytes32 root,
        uint64 claimedLength,
        uint64 actualLength,
        bytes calldata finalChunk,
        bytes32[] calldata rightEdge
    ) internal pure returns (bool overclaimProven) {
        // Only claimed > actual is actionable; everything else passes.
        if (claimedLength <= actualLength) return false;
        return verifyBaoLength(root, actualLength, finalChunk, rightEdge);
    }

    /// @notice numChunks = ceil(length/1024), with empty input = 1 chunk.
    function numChunks(uint64 length) internal pure returns (uint256) {
        if (length == 0) return 1;
        unchecked {
            return (uint256(length) + CHUNK_LEN - 1) / CHUNK_LEN;
        }
    }

    /// @notice Number of right-edge sibling CVs required for `n` chunks.
    function siblingCount(uint256 n) internal pure returns (uint256 c) {
        while (n > 1) {
            n = n - _largestPow2Below(n);
            unchecked {
                ++c;
            }
        }
    }

    /// @dev Largest power of two strictly less than n (n >= 2).
    function _largestPow2Below(uint256 n) private pure returns (uint256 k) {
        k = 1;
        while (k << 1 < n) {
            k <<= 1;
        }
    }

    // -----------------------------------------------------------------------
    // BLAKE3 leaf (chunk) hashing
    // -----------------------------------------------------------------------

    /// @dev Chaining value of one chunk (<= 1024 bytes). `counter` is the chunk
    ///      index; `isRoot` applies ROOT to the final block (single-chunk input).
    function _chunkCV(bytes calldata chunk, uint256 counter, bool isRoot) internal pure returns (bytes32 cv) {
        uint256 len = chunk.length;
        uint256 nblocks = len == 0 ? 1 : (len + BLOCK_LEN - 1) / BLOCK_LEN;
        cv = IV_BYTES;
        for (uint256 b = 0; b < nblocks; ) {
            uint256 start = b * BLOCK_LEN;
            uint256 rem = len - start;
            uint256 blen = rem >= BLOCK_LEN ? BLOCK_LEN : rem;

            (bytes32 m0, bytes32 m1) = _loadBlock(chunk, start, blen);

            uint256 flags;
            if (b == 0) flags |= CHUNK_START;
            if (b == nblocks - 1) {
                flags |= CHUNK_END;
                if (isRoot) flags |= ROOT;
            }
            cv = _compressBlock(cv, m0, m1, counter, blen, flags);
            unchecked {
                ++b;
            }
        }
    }

    /// @dev Load a 64-byte block from calldata `chunk` at `start` (blen valid
    ///      bytes), zero-padded, as two bytes32 words in natural byte order.
    function _loadBlock(bytes calldata chunk, uint256 start, uint256 blen)
        private
        pure
        returns (bytes32 m0, bytes32 m1)
    {
        assembly {
            let p := mload(0x40)
            mstore(p, 0)
            mstore(add(p, 32), 0)
            calldatacopy(p, add(chunk.offset, start), blen)
            m0 := mload(p)
            m1 := mload(add(p, 32))
        }
    }

    // -----------------------------------------------------------------------
    // BLAKE3 single-block compression (first-8-words output)
    // -----------------------------------------------------------------------

    /// @dev BLAKE3 compression of one 64-byte block. `cvIn` is the input
    ///      chaining value (BLAKE3 CV byte order); `m0||m1` is the block.
    ///      Returns the first 8 output words serialised little-endian.
    function _compressBlock(bytes32 cvIn, bytes32 m0, bytes32 m1, uint256 counter, uint256 blen, uint256 flags)
        internal
        pure
        returns (bytes32 out)
    {
        assembly {
            let sp := mload(0x40) // 16 state words
            let ma := add(sp, 0x200) // message buffer A
            let mb := add(ma, 0x200) // message buffer B (ping-pong)
            let ob := add(mb, 0x200) // 32-byte output buffer

            function rotr(x, n) -> r {
                r := and(or(shr(n, x), shl(sub(32, n), x)), 0xffffffff)
            }
            // little-endian 32-bit word i (0..7) of a 32-byte value `w`
            function le(w, i) -> r {
                let b := mul(i, 4)
                r :=
                    or(
                        or(byte(b, w), shl(8, byte(add(b, 1), w))),
                        or(shl(16, byte(add(b, 2), w)), shl(24, byte(add(b, 3), w)))
                    )
            }
            function gmix(s, ia, ib, ic, id, mx, my) {
                let pa := add(s, mul(ia, 32))
                let pb := add(s, mul(ib, 32))
                let pcc := add(s, mul(ic, 32))
                let pd := add(s, mul(id, 32))
                let a := mload(pa)
                let bb := mload(pb)
                let c := mload(pcc)
                let d := mload(pd)
                a := and(add(add(a, bb), mx), 0xffffffff)
                d := rotr(xor(d, a), 16)
                c := and(add(c, d), 0xffffffff)
                bb := rotr(xor(bb, c), 12)
                a := and(add(add(a, bb), my), 0xffffffff)
                d := rotr(xor(d, a), 8)
                c := and(add(c, d), 0xffffffff)
                bb := rotr(xor(bb, c), 7)
                mstore(pa, a)
                mstore(pb, bb)
                mstore(pcc, c)
                mstore(pd, d)
            }

            // ---- state init: v[0..7]=cvIn words, v[8..11]=IV[0..3],
            //      v12=counter low, v13=counter high, v14=block_len, v15=flags
            mstore(add(sp, mul(0, 32)), le(cvIn, 0))
            mstore(add(sp, mul(1, 32)), le(cvIn, 1))
            mstore(add(sp, mul(2, 32)), le(cvIn, 2))
            mstore(add(sp, mul(3, 32)), le(cvIn, 3))
            mstore(add(sp, mul(4, 32)), le(cvIn, 4))
            mstore(add(sp, mul(5, 32)), le(cvIn, 5))
            mstore(add(sp, mul(6, 32)), le(cvIn, 6))
            mstore(add(sp, mul(7, 32)), le(cvIn, 7))
            mstore(add(sp, mul(8, 32)), 0x6a09e667)
            mstore(add(sp, mul(9, 32)), 0xbb67ae85)
            mstore(add(sp, mul(10, 32)), 0x3c6ef372)
            mstore(add(sp, mul(11, 32)), 0xa54ff53a)
            mstore(add(sp, mul(12, 32)), and(counter, 0xffffffff))
            mstore(add(sp, mul(13, 32)), and(shr(32, counter), 0xffffffff))
            mstore(add(sp, mul(14, 32)), and(blen, 0xffffffff))
            mstore(add(sp, mul(15, 32)), and(flags, 0xffffffff))

            // ---- message block words (little-endian) from m0 (words 0..7), m1 (8..15)
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } { mstore(add(ma, mul(i, 32)), le(m0, i)) }
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } { mstore(add(ma, mul(add(i, 8), 32)), le(m1, i)) }

            // ---- 7 rounds, permuting the message buffer between rounds
            let cur := ma
            let oth := mb
            for { let r := 0 } lt(r, 7) { r := add(r, 1) } {
                gmix(sp, 0, 4, 8, 12, mload(add(cur, mul(0, 32))), mload(add(cur, mul(1, 32))))
                gmix(sp, 1, 5, 9, 13, mload(add(cur, mul(2, 32))), mload(add(cur, mul(3, 32))))
                gmix(sp, 2, 6, 10, 14, mload(add(cur, mul(4, 32))), mload(add(cur, mul(5, 32))))
                gmix(sp, 3, 7, 11, 15, mload(add(cur, mul(6, 32))), mload(add(cur, mul(7, 32))))
                gmix(sp, 0, 5, 10, 15, mload(add(cur, mul(8, 32))), mload(add(cur, mul(9, 32))))
                gmix(sp, 1, 6, 11, 12, mload(add(cur, mul(10, 32))), mload(add(cur, mul(11, 32))))
                gmix(sp, 2, 7, 8, 13, mload(add(cur, mul(12, 32))), mload(add(cur, mul(13, 32))))
                gmix(sp, 3, 4, 9, 14, mload(add(cur, mul(14, 32))), mload(add(cur, mul(15, 32))))
                if lt(r, 6) {
                    // oth[i] = cur[MSG_PERMUTATION[i]]
                    // MSG_PERMUTATION = [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8]
                    mstore(add(oth, mul(0, 32)), mload(add(cur, mul(2, 32))))
                    mstore(add(oth, mul(1, 32)), mload(add(cur, mul(6, 32))))
                    mstore(add(oth, mul(2, 32)), mload(add(cur, mul(3, 32))))
                    mstore(add(oth, mul(3, 32)), mload(add(cur, mul(10, 32))))
                    mstore(add(oth, mul(4, 32)), mload(add(cur, mul(7, 32))))
                    mstore(add(oth, mul(5, 32)), mload(add(cur, mul(0, 32))))
                    mstore(add(oth, mul(6, 32)), mload(add(cur, mul(4, 32))))
                    mstore(add(oth, mul(7, 32)), mload(add(cur, mul(13, 32))))
                    mstore(add(oth, mul(8, 32)), mload(add(cur, mul(1, 32))))
                    mstore(add(oth, mul(9, 32)), mload(add(cur, mul(11, 32))))
                    mstore(add(oth, mul(10, 32)), mload(add(cur, mul(12, 32))))
                    mstore(add(oth, mul(11, 32)), mload(add(cur, mul(5, 32))))
                    mstore(add(oth, mul(12, 32)), mload(add(cur, mul(9, 32))))
                    mstore(add(oth, mul(13, 32)), mload(add(cur, mul(14, 32))))
                    mstore(add(oth, mul(14, 32)), mload(add(cur, mul(15, 32))))
                    mstore(add(oth, mul(15, 32)), mload(add(cur, mul(8, 32))))
                    let t := cur
                    cur := oth
                    oth := t
                }
            }

            // ---- finalize: out word i = state[i] ^ state[i+8], little-endian
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                let w := and(xor(mload(add(sp, mul(i, 32))), mload(add(sp, mul(add(i, 8), 32)))), 0xffffffff)
                let p := add(ob, mul(i, 4))
                mstore8(p, w)
                mstore8(add(p, 1), shr(8, w))
                mstore8(add(p, 2), shr(16, w))
                mstore8(add(p, 3), shr(24, w))
            }
            out := mload(ob)
        }
    }
}

/// @notice External wrapper for calling as a contract / gas benchmarking.
contract BaoLengthVerifierHarness {
    function verifyBaoLength(
        bytes32 root,
        uint64 actualLength,
        bytes calldata finalChunk,
        bytes32[] calldata rightEdge
    ) external pure returns (bool) {
        return BaoLengthVerifier.verifyBaoLength(root, actualLength, finalChunk, rightEdge);
    }

    function proveOverclaim(
        bytes32 root,
        uint64 claimedLength,
        uint64 actualLength,
        bytes calldata finalChunk,
        bytes32[] calldata rightEdge
    ) external pure returns (bool) {
        return BaoLengthVerifier.proveOverclaim(root, claimedLength, actualLength, finalChunk, rightEdge);
    }

    function siblingCount(uint256 n) external pure returns (uint256) {
        return BaoLengthVerifier.siblingCount(n);
    }

    function numChunks(uint64 length) external pure returns (uint256) {
        return BaoLengthVerifier.numChunks(length);
    }

    /// @dev Microbenchmark hook: one BLAKE3 block compression.
    function compressBlock(bytes32 cv, bytes32 m0, bytes32 m1, uint256 counter, uint256 blen, uint256 flags)
        external
        pure
        returns (bytes32)
    {
        return BaoLengthVerifier._compressBlock(cv, m0, m1, counter, blen, flags);
    }
}
