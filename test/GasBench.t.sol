// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {BaoLengthVerifier, BaoLengthVerifierHarness} from "../src/BaoLengthVerifier.sol";

/// @notice Gas benchmarks. Run with:  forge test --match-contract GasBench -vv
///
/// Reports, per case: proof calldata size, its intrinsic calldata gas, the
/// number of BLAKE3 compressions (final-chunk blocks + right-edge parents), and
/// the total measured verification gas (external call path). A single-block
/// compression microbenchmark isolates the per-compression cost.
contract GasBenchTest is Test {
    BaoLengthVerifierHarness h;

    function setUp() public {
        h = new BaoLengthVerifierHarness();
    }

    struct Proof {
        bytes32 root;
        uint64 length;
        bytes finalChunk;
        bytes32[] rightEdge;
    }

    function _prove(uint256 length, uint256 seed) internal returns (Proof memory p) {
        string[] memory cmd = new string[](4);
        cmd[0] = "./.venv/bin/python";
        cmd[1] = "script/prove.py";
        cmd[2] = vm.toString(length);
        cmd[3] = vm.toString(seed);
        bytes memory res = vm.ffi(cmd);
        (bytes32 root, uint64 len, bytes memory fc, bytes32[] memory edge) =
            abi.decode(res, (bytes32, uint64, bytes, bytes32[]));
        p = Proof(root, len, fc, edge);
    }

    function _calldataGas(bytes memory encoded) internal pure returns (uint256 g) {
        for (uint256 i = 0; i < encoded.length; i++) {
            g += encoded[i] == 0 ? 4 : 16;
        }
    }

    function _bench(string memory label, Proof memory p, bool expectTrue) internal {
        bytes memory encoded =
            abi.encodeWithSelector(h.verifyBaoLength.selector, p.root, p.length, p.finalChunk, p.rightEdge);
        uint256 nblocks = p.finalChunk.length == 0 ? 1 : (p.finalChunk.length + 63) / 64;
        uint256 compressions = nblocks + p.rightEdge.length;

        uint256 g0 = gasleft();
        bool ok = h.verifyBaoLength(p.root, p.length, p.finalChunk, p.rightEdge);
        uint256 used = g0 - gasleft();
        if (expectTrue) require(ok, "expected valid proof");

        emit log_string(
            string.concat(
                "== ",
                label,
                " | len=",
                vm.toString(uint256(p.length)),
                " chunks=",
                vm.toString(BaoLengthVerifier.numChunks(p.length))
            )
        );
        emit log_named_uint("  siblings (tree traversal)", p.rightEdge.length);
        emit log_named_uint("  final-chunk blocks", nblocks);
        emit log_named_uint("  BLAKE3 compressions", compressions);
        emit log_named_uint("  calldata bytes", encoded.length);
        emit log_named_uint("  calldata gas (intrinsic)", _calldataGas(encoded));
        emit log_named_uint("  TOTAL verify gas (measured)", used);
    }

    function test_Bench_ByChunkCount() public {
        _bench("1 chunk", _prove(1024, 3), true);
        _bench("2 chunks", _prove(2048, 3), true);
        _bench("3 chunks", _prove(3072, 3), true);
        _bench("4 chunks", _prove(4096, 3), true);
        _bench("8 chunks", _prove(8192, 3), true);
        _bench("16 chunks", _prove(16384, 3), true);
        _bench("1024 chunks (2^20 bytes / 1 MiB)", _prove(1048576, 3), true);
    }

    /// @notice 1 GiB-equivalent tree DEPTH without materializing the file.
    ///         Synthetic proof: real geometry (2^20 chunks, 20 right-edge
    ///         siblings, full 1024-byte final chunk) but arbitrary CV values, so
    ///         verify() executes the full 36-compression path and returns false.
    function test_Bench_1GiB_Depth_Synthetic() public {
        uint64 length = uint64(1 << 30); // 1 GiB
        uint256 n = BaoLengthVerifier.numChunks(length); // 2^20
        uint256 sc = BaoLengthVerifier.siblingCount(n); // 20
        bytes memory finalChunk = new bytes(1024); // full final chunk
        for (uint256 i = 0; i < 1024; i++) {
            finalChunk[i] = bytes1(uint8(i));
        }
        bytes32[] memory edge = new bytes32[](sc);
        for (uint256 i = 0; i < sc; i++) {
            edge[i] = keccak256(abi.encode(i));
        }
        bytes32 fakeRoot = bytes32(0);
        Proof memory p = Proof(fakeRoot, length, finalChunk, edge);
        _bench("1 GiB depth (synthetic, verify=false)", p, false);
    }

    function test_Bench_SingleCompression() public {
        bytes32 cv = BaoLengthVerifier.IV_BYTES;
        bytes32 m0 = keccak256("m0");
        bytes32 m1 = keccak256("m1");
        uint256 g0 = gasleft();
        h.compressBlock(cv, m0, m1, 0, 64, BaoLengthVerifier.PARENT);
        uint256 used = g0 - gasleft();
        emit log_named_uint("single BLAKE3 compression gas (incl. call overhead)", used);
    }
}
