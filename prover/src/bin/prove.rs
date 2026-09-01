//! prove <length> [seed]
//!
//! Prints the ABI-encoding of (bytes32 root, uint64 length, bytes finalChunk,
//! bytes32[] rightEdge) as a 0x-hex string (the format Foundry's vm.ffi expects).

use bao_length_prover::{make_data, make_proof};
use ethabi::{encode, Token};
use ethereum_types::U256;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let length: usize = args[1].parse().expect("length");
    let seed: u64 = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(0);

    let data = make_data(length, seed);
    let p = make_proof(&data);

    let edge: Vec<Token> = p.right_edge.iter().map(|cv| Token::FixedBytes(cv.to_vec())).collect();
    let enc = encode(&[
        Token::FixedBytes(p.root.to_vec()),
        Token::Uint(U256::from(p.length)),
        Token::Bytes(p.final_chunk),
        Token::Array(edge),
    ]);
    print!("0x{}", hex::encode(&enc));
}

// Minimal local hex encoder to avoid an extra dependency.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}
