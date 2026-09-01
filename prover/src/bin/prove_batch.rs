//! prove-batch <count> <seed> [maxlen]
//!
//! Prints the ABI-encoding of parallel arrays
//! (uint64[] lengths, bytes32[] roots, bytes[] finalChunks, bytes32[][] edges)
//! for randomized differential testing.

use bao_length_prover::{make_data, make_proof};
use ethabi::{encode, Token};
use ethereum_types::U256;

// Deterministic length picker (SplitMix64), independent of data filler.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let count: usize = args[1].parse().expect("count");
    let seed: u64 = args[2].parse().expect("seed");
    let maxlen: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(70000);

    let mut rng = Rng(seed);
    let (mut lens, mut roots, mut finals, mut edges) = (vec![], vec![], vec![], vec![]);
    for i in 0..count {
        let length = (rng.next() as usize) % (maxlen + 1);
        let data = make_data(length, seed ^ (i as u64));
        let p = make_proof(&data);
        lens.push(Token::Uint(U256::from(p.length)));
        roots.push(Token::FixedBytes(p.root.to_vec()));
        finals.push(Token::Bytes(p.final_chunk));
        edges.push(Token::Array(
            p.right_edge.iter().map(|cv| Token::FixedBytes(cv.to_vec())).collect(),
        ));
    }

    let enc = encode(&[
        Token::Array(lens),
        Token::Array(roots),
        Token::Array(finals),
        Token::Array(edges),
    ]);
    print!("0x{}", hex_encode(&enc));
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
