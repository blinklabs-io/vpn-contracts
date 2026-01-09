//! VPN Payment Circuit CLI
//!
//! Usage:
//!   vpn-payment-circuit prove <input.json> <output.json>
//!   vpn-payment-circuit verify <proof.json>
//!   vpn-payment-circuit keygen <params.bin>

use std::fs;
use std::path::PathBuf;

use vpn_payment_circuit::{PaymentVerificationCircuit, PrivateInputs, PublicInputs, PaymentProof};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "prove" => {
            if args.len() < 4 {
                eprintln!("Usage: {} prove <input.json> <output.json>", args[0]);
                return;
            }
            prove(&args[2], &args[3]);
        }
        "verify" => {
            if args.len() < 3 {
                eprintln!("Usage: {} verify <proof.json>", args[0]);
                return;
            }
            verify(&args[2]);
        }
        "keygen" => {
            if args.len() < 3 {
                eprintln!("Usage: {} keygen <params.bin>", args[0]);
                return;
            }
            keygen(&args[2]);
        }
        "export-verifier" => {
            if args.len() < 3 {
                eprintln!("Usage: {} export-verifier <output_dir>", args[0]);
                return;
            }
            export_verifier(&args[2]);
        }
        _ => {
            print_usage();
        }
    }
}

fn print_usage() {
    println!("VPN Payment Circuit - Halo2 ZK Proof Generator");
    println!();
    println!("Commands:");
    println!("  prove <input.json> <output.json>  Generate a proof");
    println!("  verify <proof.json>               Verify a proof");
    println!("  keygen <params.bin>               Generate proving/verification keys");
    println!("  export-verifier <output_dir>      Export Plutus verifier");
    println!();
    println!("Input JSON format:");
    println!("{{");
    println!("  \"private\": {{");
    println!("    \"secret_key\": \"<hex 32 bytes>\",");
    println!("    \"payment_amount\": <lovelace>,");
    println!("    \"sequence\": <number>");
    println!("  }},");
    println!("  \"public\": {{");
    println!("    \"pricing_tier\": <0|1|2>,");
    println!("    \"region_hash\": \"<hex 32 bytes>\",");
    println!("    \"nullifier\": \"<hex 32 bytes>\",");
    println!("    \"provider_commitment\": \"<hex 32 bytes>\",");
    println!("    \"state_root\": \"<hex 32 bytes>\"");
    println!("  }}");
    println!("}}");
}

fn prove(input_path: &str, output_path: &str) {
    println!("Generating proof...");

    // Read input
    let input_str = fs::read_to_string(input_path)
        .expect("Failed to read input file");

    let input: serde_json::Value = serde_json::from_str(&input_str)
        .expect("Failed to parse input JSON");

    // Parse private inputs
    let private = PrivateInputs {
        secret_key: hex_to_bytes32(&input["private"]["secret_key"].as_str().unwrap()),
        payment_amount: input["private"]["payment_amount"].as_u64().unwrap(),
        sequence: input["private"]["sequence"].as_u64().unwrap(),
    };

    // Parse public inputs
    let public = PublicInputs {
        pricing_tier: input["public"]["pricing_tier"].as_u64().unwrap() as u8,
        region_hash: hex_to_bytes32(&input["public"]["region_hash"].as_str().unwrap()),
        nullifier: hex_to_bytes32(&input["public"]["nullifier"].as_str().unwrap()),
        provider_commitment: hex_to_bytes32(&input["public"]["provider_commitment"].as_str().unwrap()),
        state_root: hex_to_bytes32(&input["public"]["state_root"].as_str().unwrap()),
    };

    // Create circuit
    use halo2curves::pasta::Fp;
    let _circuit = PaymentVerificationCircuit::<Fp>::new(&private, &public);

    // TODO: Generate actual proof using Halo2 proving system
    // For now, create a placeholder proof
    let proof = PaymentProof {
        proof: vec![0u8; 288], // Placeholder - actual Halo2 proof would be here
        public_inputs: public,
    };

    // Write output
    let output_str = proof.to_json().expect("Failed to serialize proof");
    fs::write(output_path, &output_str).expect("Failed to write output file");

    // Also write script format
    let script_path = PathBuf::from(output_path).with_extension("script.json");
    let script_format = proof.to_script_format();
    let script_str = serde_json::to_string_pretty(&script_format).unwrap();
    fs::write(&script_path, &script_str).expect("Failed to write script format");

    println!("Proof written to: {}", output_path);
    println!("Script format written to: {}", script_path.display());
}

fn verify(proof_path: &str) {
    println!("Verifying proof...");

    let proof_str = fs::read_to_string(proof_path)
        .expect("Failed to read proof file");

    let proof: PaymentProof = serde_json::from_str(&proof_str)
        .expect("Failed to parse proof JSON");

    // TODO: Implement actual Halo2 verification
    // For now, just validate the structure
    println!("Proof structure valid");
    println!("  Pricing tier: {}", proof.public_inputs.pricing_tier);
    println!("  Region hash: {}", hex::encode(proof.public_inputs.region_hash));
    println!("  Nullifier: {}", hex::encode(proof.public_inputs.nullifier));

    println!("\nVerification: PLACEHOLDER (actual verification not yet implemented)");
}

fn keygen(output_path: &str) {
    println!("Generating proving and verification keys...");

    // TODO: Implement key generation
    // This would involve:
    // 1. Creating the circuit with empty witnesses
    // 2. Running the setup ceremony
    // 3. Saving the proving and verification keys

    println!("Key generation: NOT YET IMPLEMENTED");
    println!("Output would be written to: {}", output_path);
}

fn export_verifier(output_dir: &str) {
    println!("Exporting Plutus verifier...");

    // TODO: Implement Plutus verifier export
    // This would use plutus-halo2-verifier-gen to create:
    // 1. A Plutus script that verifies Halo2 proofs
    // 2. Using the BLS12-381 primitives available in Plutus V3

    fs::create_dir_all(output_dir).expect("Failed to create output directory");

    let readme = r#"# Plutus Halo2 Verifier

This directory will contain the generated Plutus verifier for VPN payment proofs.

## Generation

The verifier is generated using `plutus-halo2-verifier-gen` which creates a Plutus
script capable of verifying Halo2 proofs using Plutus V3's BLS12-381 primitives.

## Usage

Deploy the verifier as a reference script on Cardano, then reference it in
VPN minting transactions that use Midnight ZK proofs.

## Files

- `verifier.plutus` - The compiled Plutus verifier script
- `verifier_hash.txt` - Script hash for reference in Cardano transactions

"#;

    fs::write(format!("{}/README.md", output_dir), readme)
        .expect("Failed to write README");

    println!("Verifier export: NOT YET IMPLEMENTED");
    println!("Placeholder README written to: {}/README.md", output_dir);
}

fn hex_to_bytes32(hex_str: &str) -> [u8; 32] {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).expect("Invalid hex string");
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes[..32.min(bytes.len())]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_bytes32() {
        let hex = "0102030405060708091011121314151617181920212223242526272829303132";
        let bytes = hex_to_bytes32(hex);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[31], 0x32);
    }
}
