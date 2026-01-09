//! Custom transcript hash state that matches the Aiken verifier's format
//!
//! The Aiken verifier uses a specific transcript format:
//! - Accumulates bytes directly (not incremental hashing)
//! - Uses unkeyed blake2b_256 (32-byte output)
//! - Prefixes: 0x01 for common elements, 0x00 for challenge squeeze
//! - Scalars are in little-endian format
//!
//! This differs from IOG's default Blake2bState which uses:
//! - Keyed blake2b_512 with key "Domain separator for transcript"
//! - Incremental hashing

use blake2b_simd::Params;
use halo2_proofs::halo2curves::bls12381::{Fr, G1};
use halo2_proofs::halo2curves::ff::{FromUniformBytes, PrimeField};
use halo2_proofs::halo2curves::group::GroupEncoding;
use halo2_proofs::transcript::{Hashable, Sampleable, TranscriptHash};
use std::io::{self, Read};

const PREFIX_CHALLENGE: u8 = 0x00;
const PREFIX_COMMON: u8 = 0x01;

/// Hash state that matches Aiken's transcript format.
/// Uses accumulation + blake2b_256 instead of keyed blake2b_512.
#[derive(Clone, Debug)]
pub struct AikenHashState {
    accumulated: Vec<u8>,
}

impl TranscriptHash for AikenHashState {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn init() -> Self {
        Self {
            accumulated: Vec::new(),
        }
    }

    fn absorb(&mut self, input: &Self::Input) {
        // In Aiken: common_scalar and common_point prepend 0x01 prefix
        self.accumulated.push(PREFIX_COMMON);
        self.accumulated.extend_from_slice(input);
        if self.accumulated.len() <= 200 {
            eprintln!("DEBUG absorb #{}: {} bytes, acc[{}]: {}",
                self.accumulated.len() / 33, input.len(), self.accumulated.len(),
                hex::encode(&input[..std::cmp::min(16, input.len())]));
        }
    }

    fn squeeze(&mut self) -> Self::Output {
        // In Aiken: squeeze_challenge appends 0x00 prefix then hashes
        // Compute hash: blake2b_256(accumulated || 0x00)
        let mut data = self.accumulated.clone();
        data.push(PREFIX_CHALLENGE);

        if self.accumulated.len() == 328 {
            eprintln!("DEBUG first squeeze - accumulated[0..66]: {}", hex::encode(&self.accumulated[0..66]));
            eprintln!("DEBUG first squeeze - accumulated[66..132]: {}", hex::encode(&self.accumulated[66..132]));
            eprintln!("DEBUG first squeeze - accumulated[132..181]: {}", hex::encode(&self.accumulated[132..181]));
        }
        if self.accumulated.len() == 773 {
            // This is x squeeze - print the bytes added after y squeeze
            eprintln!("DEBUG x squeeze - accumulated[674..773]: {}", hex::encode(&self.accumulated[674..773]));
            eprintln!("DEBUG x squeeze - last 32 bytes: {}", hex::encode(&self.accumulated[741..773]));
        }

        let hash = Params::new()
            .hash_length(32)
            .hash(&data);

        eprintln!("DEBUG squeeze: accumulated size: {}, hash: {}", self.accumulated.len(), hex::encode(hash.as_bytes()));

        // Update accumulated state - keep the 0x00 suffix for future squeezes
        self.accumulated.push(PREFIX_CHALLENGE);

        hash.as_bytes()[..32].to_vec()
    }
}

// Implement Hashable for G1 with our hash state
impl Hashable<AikenHashState> for G1 {
    fn to_input(&self) -> Vec<u8> {
        // Compressed G1 point encoding
        <Self as GroupEncoding>::to_bytes(self).as_ref().to_vec()
    }

    fn to_bytes(&self) -> Vec<u8> {
        <Self as GroupEncoding>::to_bytes(self).as_ref().to_vec()
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        let mut bytes = <Self as GroupEncoding>::Repr::default();
        buffer.read_exact(bytes.as_mut())?;
        Option::from(Self::from_bytes(&bytes)).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Invalid G1 point encoding")
        })
    }
}

// Implement Hashable for Fr with our hash state
impl Hashable<AikenHashState> for Fr {
    fn to_input(&self) -> Vec<u8> {
        // Little-endian scalar encoding
        self.to_repr().as_ref().to_vec()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_repr().as_ref().to_vec()
    }

    fn read(buffer: &mut impl Read) -> io::Result<Self> {
        let mut bytes = <Self as PrimeField>::Repr::default();
        buffer.read_exact(bytes.as_mut())?;
        Option::from(Self::from_repr(bytes)).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Invalid scalar encoding")
        })
    }
}

// Implement Sampleable for Fr with our hash state
impl Sampleable<AikenHashState> for Fr {
    fn sample(hash_output: Vec<u8>) -> Self {
        // The Aiken verifier uses from_bytes_little_endian which:
        // 1. Converts 32 bytes to integer (little-endian)
        // 2. Reduces modulo field_prime using simple modular reduction
        //
        // We must match this exactly - NOT use from_uniform_bytes which does
        // a different reduction strategy
        assert!(hash_output.len() == 32);

        // Convert little-endian bytes to Fr - from_repr expects little-endian
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash_output);

        // Debug: print the hash and resulting scalar
        let n = num_bigint::BigUint::from_bytes_le(&hash_output);
        eprintln!("DEBUG sample: hash={}, le_int={}", hex::encode(&hash_output), n);

        // from_repr does automatic reduction if the value exceeds the field prime
        let result = Fr::from_repr(bytes.into()).unwrap_or_else(|| {
            // If from_repr fails, do manual reduction
            // This can happen if the bytes represent a value >= field_prime
            // Convert to big integer, reduce, then convert back
            let mut n = num_bigint::BigUint::from_bytes_le(&hash_output);
            let field_prime = num_bigint::BigUint::parse_bytes(
                b"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
                16
            ).unwrap();
            eprintln!("DEBUG sample: needs reduction, n >= field_prime");
            n = n % &field_prime;
            eprintln!("DEBUG sample: after reduction n={}", n);

            let mut reduced_bytes = [0u8; 32];
            let n_bytes = n.to_bytes_le();
            reduced_bytes[..n_bytes.len()].copy_from_slice(&n_bytes);
            Fr::from_repr(reduced_bytes.into()).unwrap()
        });

        // Print the actual scalar value
        eprintln!("DEBUG sample: result repr={}", hex::encode(result.to_repr().as_ref()));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::transcript::{CircuitTranscript, Transcript};

    #[test]
    fn test_aiken_transcript_format() {
        // Test that our transcript produces the expected format
        // This matches the Aiken verifier's construct_transcript behavior

        // Create a test scalar
        let rep_bytes = hex::decode("6bbc57120c9febaa800405f895464192c4f0d00e3b1b6d6ed1274d8cda2f7753").unwrap();
        let mut rep_arr = [0u8; 32];
        rep_arr.copy_from_slice(&rep_bytes);
        let rep = Fr::from_repr(rep_arr.into()).unwrap();

        // Create transcript with our Aiken-compatible hash state
        let mut transcript: CircuitTranscript<AikenHashState> = CircuitTranscript::init();

        // Add the transcript representation as common element
        transcript.common(&rep).unwrap();

        // Squeeze a challenge
        let challenge: Fr = transcript.squeeze_challenge();

        println!("Challenge bytes: {}", hex::encode(challenge.to_repr().as_ref()));
    }

    #[test]
    fn test_accumulated_format() {
        // Test the byte accumulation format
        let mut state = AikenHashState::init();

        // Absorb a scalar (simulating common_scalar)
        let test_bytes = vec![0x01, 0x02, 0x03, 0x04];
        state.absorb(&test_bytes);

        // Check accumulated format: should be [0x01, 0x01, 0x02, 0x03, 0x04]
        assert_eq!(state.accumulated, vec![0x01, 0x01, 0x02, 0x03, 0x04]);

        // Squeeze - this hashes accumulated || 0x00
        let _hash = state.squeeze();

        // After squeeze, accumulated should have 0x00 appended
        assert_eq!(state.accumulated, vec![0x01, 0x01, 0x02, 0x03, 0x04, 0x00]);
    }
}
