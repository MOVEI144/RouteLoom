//! Deterministic seeded mutation/property test: mutates valid encoded frames
//! with a splitmix64 PRNG and asserts the decoder never crashes and always
//! returns a defined Result. No external fuzzing infrastructure.

use std::fs;
use std::path::{Path, PathBuf};

use routeloom_wire::test_security::TestSecurity;
use routeloom_wire::*;

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/golden")
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("bad hex"))
        .collect()
}

fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let start = text.find(&needle)? + needle.len();
    let rest = text[start..].trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(&stripped[..end])
    } else {
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '-'))
            .unwrap_or(rest.len());
        Some(&rest[..end])
    }
}

fn load_bases() -> Vec<(Vec<u8>, u64)> {
    let dir = golden_dir().join("valid");
    let mut bases = Vec::new();
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .expect("golden dir missing")
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    files.sort();
    for path in files {
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read vector");
        let encoded = hex_decode(field(&text, "encoded_hex").expect("encoded_hex"));
        let next_hop: u64 = field(&text, "next_hop")
            .expect("next_hop")
            .parse()
            .expect("u64");
        if !encoded.is_empty() {
            bases.push((encoded, next_hop));
        }
    }
    bases
}

#[test]
fn mutated_frames_never_crash_and_always_return_a_result() {
    let bases = load_bases();
    assert!(!bases.is_empty());
    let mut rng = SplitMix64(0x005e_ed5e_ed5e_ed00);
    let iterations = 4000;
    let mut decoded = 0_u32;
    let mut rejected = 0_u32;

    for _ in 0..iterations {
        let base = (rng.next() as usize) % bases.len();
        let mut mutated = bases[base].0.clone();
        let ops = 1 + (rng.next() % 4) as usize;
        for _ in 0..ops {
            match rng.next() % 4 {
                0 => {
                    let index = (rng.next() as usize) % mutated.len();
                    mutated[index] ^= 1 << (rng.next() % 8);
                }
                1 => {
                    let index = (rng.next() as usize) % mutated.len();
                    mutated[index] = rng.next() as u8;
                }
                2 => {
                    let keep = 1 + (rng.next() as usize) % mutated.len();
                    mutated.truncate(keep);
                }
                _ => mutated.push(rng.next() as u8),
            }
        }
        let local = if rng.next() % 4 == 0 {
            rng.next() % 8 + 1
        } else {
            bases[base].1
        };
        let mut security = TestSecurity::new();
        let mut opened = LinkOpenedFrame::default();
        match open_link(&mutated, local, &mut security, &mut opened) {
            Ok(()) => {
                decoded += 1;
                let mut out = PlainFrame::default();
                let _ = open_end(&opened, opened.header.destination, &mut security, &mut out);
            }
            Err(_) => rejected += 1,
        }
    }
    println!("mutation loop: {decoded} decoded, {rejected} rejected of {iterations}");
    assert!(rejected > 0);
}
