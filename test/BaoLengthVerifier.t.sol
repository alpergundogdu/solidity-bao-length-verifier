// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {BaoLengthVerifier, BaoLengthVerifierHarness} from "../src/BaoLengthVerifier.sol";

/// @dev All proofs come from script/prove.py (the audited Python reference,
///      cross-checked against the official `blake3` package) via FFI, so these
///      are true differential tests against ground truth.
contract BaoLengthVerifierTest is Test {
    struct Proof {
        bytes32 root;
        uint64 length;
        bytes finalChunk;
        bytes32[] rightEdge;
    }

    // Official BLAKE3 hash of the empty input (independent known-answer anchor).
    bytes32 constant EMPTY_ROOT = 0xaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262;

    BaoLengthVerifierHarness h;

    function setUp() public {
        h = new BaoLengthVerifierHarness();
    }

    function _prove(uint256 length, uint256 seed) internal returns (Proof memory p) {
        string[] memory cmd = new string[](3);
        cmd[0] = "prover/target/release/prove";
        cmd[1] = vm.toString(length);
        cmd[2] = vm.toString(seed);
        bytes memory res = vm.ffi(cmd);
        (bytes32 root, uint64 len, bytes memory fc, bytes32[] memory edge) =
            abi.decode(res, (bytes32, uint64, bytes, bytes32[]));
        p.root = root;
        p.length = len;
        p.finalChunk = fc;
        p.rightEdge = edge;
    }

    function _verify(Proof memory p, uint64 claimedLength) internal view returns (bool) {
        return h.verifyBaoLength(p.root, claimedLength, p.finalChunk, p.rightEdge);
    }

    // ------------------------------------------------------------------
    // Known-answer anchor (no FFI): empty input.
    // ------------------------------------------------------------------
    function test_EmptyKnownAnswer() public view {
        bytes memory empty = "";
        bytes32[] memory none = new bytes32[](0);
        assertTrue(h.verifyBaoLength(EMPTY_ROOT, 0, empty, none), "empty root");
    }

    // ------------------------------------------------------------------
    // Mandatory lengths: verifier accepts the true length.
    // ------------------------------------------------------------------
    function test_MandatoryLengths() public {
        uint256[] memory L = _mandatory();
        for (uint256 i = 0; i < L.length; i++) {
            Proof memory p = _prove(L[i], 1);
            assertEq(uint256(p.length), L[i], "length roundtrip");
            assertTrue(_verify(p, uint64(L[i])), string.concat("accept len ", vm.toString(L[i])));
        }
    }

    // ------------------------------------------------------------------
    // Adversarial length claims: for a proof generated for the true length,
    // any other claimed length must be rejected (exact-length binding).
    // ------------------------------------------------------------------
    function test_AdversarialClaims() public {
        uint256[] memory L = _mandatory();
        for (uint256 i = 0; i < L.length; i++) {
            uint256 n = L[i];
            if (n < 2) continue;
            Proof memory p = _prove(n, 2);
            // n-1 (partial-chunk boundary), n+1, and cross-bucket claims
            assertFalse(_verify(p, uint64(n - 1)), "reject n-1");
            assertFalse(_verify(p, uint64(n + 1)), "reject n+1");
            if (n > 1024) assertFalse(_verify(p, uint64(n - 1024)), "reject n-1024");
            assertFalse(_verify(p, uint64(n + 1024)), "reject n+1024");
        }
    }

    // ------------------------------------------------------------------
    // Security: the SAME witness (finalChunk + rightEdge) must verify for the
    // true length ONLY. Crucially this covers the two failure modes that the
    // byte-free scheme could not distinguish:
    //   (a) different chunk count with the same siblingCount, and
    //   (b) same chunk count, different exact byte length.
    // ------------------------------------------------------------------
    function test_Security_SameWitness_OnlyTrueLengthVerifies() public {
        // 1500 bytes: 2 chunks, siblingCount 1. The byte-free scheme accepted
        // 2049 (3 chunks, siblingCount 1) with this witness; the sound scheme
        // must reject it.
        Proof memory p = _prove(1500, 7);
        assertTrue(_verify(p, 1500), "true length");
        assertFalse(_verify(p, 2049), "diff chunk-count, same siblingCount"); // (a)
        assertFalse(_verify(p, 1499), "same chunk-count, off by one byte"); // (b)
        assertFalse(_verify(p, 1501), "same chunk-count, off by one byte"); // (b)

        // Another siblingCount collision: 2 chunks vs 5 chunks (both sc=1).
        Proof memory q = _prove(2000, 8); // 2 chunks
        assertTrue(_verify(q, 2000), "true");
        assertFalse(_verify(q, 4097), "5 chunks, same siblingCount 1");
    }

    // Sweep every claimed length in a window around the true length; only the
    // exact true length may verify.
    function test_Security_WindowSweep() public {
        uint256 trueLen = 3000; // 3 chunks
        Proof memory p = _prove(trueLen, 9);
        for (uint256 c = trueLen - 40; c <= trueLen + 40; c++) {
            bool ok = _verify(p, uint64(c));
            assertEq(ok, c == trueLen, string.concat("claim ", vm.toString(c)));
        }
    }

    // ------------------------------------------------------------------
    // Differential fuzz against the reference (via FFI oracle).
    // ------------------------------------------------------------------
    function test_Differential_Batch() public {
        uint256 count = 400;
        string[] memory cmd = new string[](4);
        cmd[0] = "prover/target/release/prove-batch";
        cmd[1] = vm.toString(count);
        cmd[2] = vm.toString(uint256(1234));
        cmd[3] = vm.toString(uint256(40000));
        bytes memory res = vm.ffi(cmd);
        (uint64[] memory lens, bytes32[] memory roots, bytes[] memory finals, bytes32[][] memory edges) =
            abi.decode(res, (uint64[], bytes32[], bytes[], bytes32[][]));
        assertEq(lens.length, count, "count");
        for (uint256 i = 0; i < count; i++) {
            assertTrue(h.verifyBaoLength(roots[i], lens[i], finals[i], edges[i]), "accept true length");
            assertFalse(h.verifyBaoLength(roots[i], lens[i] + 1, finals[i], edges[i]), "reject length+1");
            if (lens[i] >= 1) {
                assertFalse(h.verifyBaoLength(roots[i], lens[i] - 1, finals[i], edges[i]), "reject length-1");
            }
        }
    }

    function testFuzz_Differential(uint32 rawLen, uint16 seed) public {
        uint256 length = uint256(rawLen) % 200_001; // 0 .. 200000
        Proof memory p = _prove(length, seed);
        assertTrue(_verify(p, uint64(length)), "accept true length");
        if (length >= 1) assertFalse(_verify(p, uint64(length - 1)), "reject length-1");
        assertFalse(_verify(p, uint64(length + 1)), "reject length+1");
    }

    // sibling-count / numChunks geometry sanity vs the reference expectations.
    function test_Geometry() public pure {
        assertEq(BaoLengthVerifier.numChunks(0), 1);
        assertEq(BaoLengthVerifier.numChunks(1), 1);
        assertEq(BaoLengthVerifier.numChunks(1024), 1);
        assertEq(BaoLengthVerifier.numChunks(1025), 2);
        assertEq(BaoLengthVerifier.numChunks(2048), 2);
        assertEq(BaoLengthVerifier.numChunks(2049), 3);

        assertEq(BaoLengthVerifier.siblingCount(1), 0);
        assertEq(BaoLengthVerifier.siblingCount(2), 1);
        assertEq(BaoLengthVerifier.siblingCount(3), 1);
        assertEq(BaoLengthVerifier.siblingCount(4), 2);
        assertEq(BaoLengthVerifier.siblingCount(5), 1);
        assertEq(BaoLengthVerifier.siblingCount(6), 2);
        assertEq(BaoLengthVerifier.siblingCount(7), 2);
        assertEq(BaoLengthVerifier.siblingCount(8), 3);
    }

    function _mandatory() internal pure returns (uint256[] memory L) {
        uint256[26] memory a = [
            uint256(0),
            1,
            2,
            1023,
            1024,
            1025,
            16383,
            16384,
            16385,
            32767,
            32768,
            32769,
            65535,
            65536,
            65537,
            100000,
            100001,
            1048576, // 1 MiB
            1048577, // 1 MiB + 1
            3072,
            3073,
            5000,
            7000,
            9000,
            50000,
            123456
        ];
        L = new uint256[](a.length);
        for (uint256 i = 0; i < a.length; i++) {
            L[i] = a[i];
        }
    }
}
