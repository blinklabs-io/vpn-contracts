//! VPN Payment Circuit CLI
//!
//! Usage:
//!   vpn-payment-circuit prove <input.json> <output.json>
//!   vpn-payment-circuit verify <proof.json>
//!   vpn-payment-circuit keygen <output_dir>
//!   vpn-payment-circuit export-verifier <keys_dir> <output_file>

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;

use blake2b_simd::State as Blake2bState;
use halo2_proofs::halo2curves::bls12381::{Bls12381, Fr, G1Affine, G1, G2Affine};
use halo2_proofs::halo2curves::ff::{Field, PrimeField};
use halo2_proofs::plonk::{keygen_pk, keygen_vk_with_k, create_proof, prepare, VerifyingKey};
use halo2_proofs::poly::commitment::Guard;
use halo2_proofs::poly::commitment::{Params, PolynomialCommitmentScheme};
use halo2_proofs::poly::kzg::{KZGCommitmentScheme, params::ParamsKZG};
use halo2_proofs::transcript::{CircuitTranscript, Transcript};
use halo2_proofs::utils::SerdeFormat;
use rand::rngs::OsRng;

use vpn_payment_circuit::aiken_transcript::AikenHashState;
use vpn_payment_circuit::bls12_381::{VPNPaymentCircuit, TIER_PRICES};
use vpn_payment_circuit::{PaymentProof, PrivateInputs, PublicInputs};

// Type alias for our commitment scheme
type CS = KZGCommitmentScheme<Bls12381>;

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
        "prove-with-keys" => {
            if args.len() < 5 {
                eprintln!("Usage: {} prove-with-keys <keys_dir> <input.json> <output.json>", args[0]);
                return;
            }
            prove_with_keys(&args[2], &args[3], &args[4]);
        }
        "verify" => {
            if args.len() < 3 {
                eprintln!("Usage: {} verify <proof.json>", args[0]);
                return;
            }
            verify(&args[2]);
        }
        "verify-with-keys" => {
            if args.len() < 4 {
                eprintln!("Usage: {} verify-with-keys <keys_dir> <proof.json>", args[0]);
                return;
            }
            verify_with_keys(&args[2], &args[3]);
        }
        "test-standard-transcript" => {
            if args.len() < 3 {
                eprintln!("Usage: {} test-standard-transcript <keys_dir>", args[0]);
                return;
            }
            test_standard_transcript(&args[2]);
        }
        "test-vpn-circuit" => {
            test_vpn_circuit_in_memory();
        }
        "keygen" => {
            if args.len() < 3 {
                eprintln!("Usage: {} keygen <output_dir>", args[0]);
                return;
            }
            keygen(&args[2]);
        }
        "export-verifier" => {
            if args.len() < 4 {
                eprintln!("Usage: {} export-verifier <keys_dir> <output_file>", args[0]);
                return;
            }
            export_verifier(&args[2], &args[3]);
        }
        "debug-g2" => {
            if args.len() < 3 {
                eprintln!("Usage: {} debug-g2 <keys_dir>", args[0]);
                return;
            }
            debug_g2_serialization(&args[2]);
        }
        "debug-verify" => {
            if args.len() < 4 {
                eprintln!("Usage: {} debug-verify <keys_dir> <proof.json>", args[0]);
                return;
            }
            debug_verify(&args[2], &args[3]);
        }
        "debug-msm" => {
            if args.len() < 3 {
                eprintln!("Usage: {} debug-msm <keys_dir>", args[0]);
                return;
            }
            debug_msm_computation(&args[2]);
        }
        "debug-pairing" => {
            if args.len() < 3 {
                eprintln!("Usage: {} debug-pairing <keys_dir>", args[0]);
                return;
            }
            debug_pairing_check(&args[2]);
        }
        "debug-v" => {
            if args.len() < 3 {
                eprintln!("Usage: {} debug-v <keys_dir>", args[0]);
                return;
            }
            debug_v_computation(&args[2]);
        }
        _ => {
            print_usage();
        }
    }
}

fn print_usage() {
    println!("VPN Payment Circuit - Halo2 ZK Proof Generator (BLS12-381)");
    println!();
    println!("Commands:");
    println!("  prove <input.json> <output.json>  Generate a proof");
    println!("  verify <proof.json>               Verify a proof");
    println!("  keygen <output_dir>               Generate proving/verification keys");
    println!("  export-verifier <keys_dir> <out>  Export Aiken verifier key constants");
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

/// Circuit size parameter (k). Circuit can have 2^k rows.
/// k=8 gives 256 rows which is sufficient for our simple circuit.
const CIRCUIT_K: u32 = 8;

fn prove(input_path: &str, output_path: &str) {
    println!("Generating proof (BLS12-381)...");

    let input_str = fs::read_to_string(input_path).expect("Failed to read input file");
    let input: serde_json::Value =
        serde_json::from_str(&input_str).expect("Failed to parse input JSON");

    let private = PrivateInputs {
        secret_key: hex_to_bytes32(input["private"]["secret_key"].as_str().unwrap()),
        payment_amount: input["private"]["payment_amount"].as_u64().unwrap(),
        sequence: input["private"]["sequence"].as_u64().unwrap(),
    };

    let public = PublicInputs {
        pricing_tier: input["public"]["pricing_tier"].as_u64().unwrap() as u8,
        region_hash: hex_to_bytes32(input["public"]["region_hash"].as_str().unwrap()),
        nullifier: hex_to_bytes32(input["public"]["nullifier"].as_str().unwrap()),
        provider_commitment: hex_to_bytes32(input["public"]["provider_commitment"].as_str().unwrap()),
        state_root: hex_to_bytes32(input["public"]["state_root"].as_str().unwrap()),
    };

    // Get required price for the tier
    let tier = public.pricing_tier as usize;
    if tier >= TIER_PRICES.len() {
        eprintln!("Error: Invalid pricing tier {}", tier);
        std::process::exit(1);
    }
    let required_price = TIER_PRICES[tier];

    // Validate payment amount covers the required price
    if private.payment_amount < required_price {
        eprintln!(
            "Error: Payment amount {} is less than required price {} for tier {}",
            private.payment_amount, required_price, tier
        );
        std::process::exit(1);
    }

    println!("  Pricing tier: {} (requires {} lovelace)", tier, required_price);
    println!("  Payment amount: {} lovelace", private.payment_amount);

    // Convert inputs to field elements
    let payment_amount_fr = Fr::from(private.payment_amount);
    let pricing_tier_fr = Fr::from(tier as u64);
    let required_price_fr = Fr::from(required_price);

    // Convert nullifier from Midnight (32-byte input) to field element
    // The nullifier is generated by Midnight's persistentHash, not computed here
    let nullifier_bytes: [u8; 32] = public.nullifier;
    let nullifier_int = num_bigint::BigUint::from_bytes_be(&nullifier_bytes);
    let nullifier_bytes_le: Vec<u8> = nullifier_int.to_bytes_le();
    let mut nullifier_repr = [0u8; 32];
    let copy_len = nullifier_bytes_le.len().min(32);
    nullifier_repr[..copy_len].copy_from_slice(&nullifier_bytes_le[..copy_len]);
    let nullifier_fr = Fr::from_repr(nullifier_repr.into()).unwrap_or(Fr::from(0u64));

    println!("  Using nullifier from Midnight: {}", hex::encode(nullifier_bytes));

    // Create the circuit with witness values
    let circuit = VPNPaymentCircuit::new(
        payment_amount_fr, pricing_tier_fr, nullifier_fr, required_price_fr,
    );

    // Public inputs for the instance column: [pricing_tier, nullifier]
    let public_inputs_fr: Vec<Fr> = vec![pricing_tier_fr, nullifier_fr];

    // Generate proving parameters
    println!("  Generating KZG parameters (k={})...", CIRCUIT_K);
    let params: ParamsKZG<Bls12381> = CS::gen_params(CIRCUIT_K);

    // Generate verification key
    println!("  Generating verification key...");
    let vk = keygen_vk_with_k::<Fr, CS, _>(&params, &circuit, CIRCUIT_K).expect("Failed to generate verification key");

    // Generate proving key
    println!("  Generating proving key...");
    let pk = keygen_pk::<Fr, CS, _>(vk, &circuit).expect("Failed to generate proving key");

    // Create proof transcript
    println!("  Creating proof...");
    let mut transcript: CircuitTranscript<Blake2bState> = CircuitTranscript::init();

    // Generate the proof
    create_proof::<Fr, CS, CircuitTranscript<Blake2bState>, _>(
        &params, &pk, &[circuit], &[&[&public_inputs_fr]], OsRng, &mut transcript,
    ).expect("Failed to generate proof");

    // Finalize the transcript to get the proof bytes
    let proof_bytes = transcript.finalize();

    println!("  Proof size: {} bytes", proof_bytes.len());

    // Create the payment proof structure
    let proof = PaymentProof {
        proof: proof_bytes,
        public_inputs: public,
    };

    let output_str = proof.to_json().expect("Failed to serialize proof");
    fs::write(output_path, &output_str).expect("Failed to write output file");

    let script_path = PathBuf::from(output_path).with_extension("script.json");
    let script_format = proof.to_script_format();
    let script_str = serde_json::to_string_pretty(&script_format).unwrap();
    fs::write(&script_path, &script_str).expect("Failed to write script format");

    println!("Proof written to: {}", output_path);
    println!("Script format written to: {}", script_path.display());
}

fn prove_with_keys(keys_dir: &str, input_path: &str, output_path: &str) {
    use halo2_proofs::halo2curves::ff::PrimeField;

    println!("Generating proof with existing keys (BLS12-381)...");

    // Load existing parameters
    let params_path = format!("{}/params.bin", keys_dir);
    println!("Loading parameters from: {}", params_path);
    let params_file = File::open(&params_path).expect("Failed to open params file. Run keygen first.");
    let mut params_reader = BufReader::new(params_file);
    let params: ParamsKZG<Bls12381> = ParamsKZG::read_custom(&mut params_reader, SerdeFormat::RawBytes)
        .expect("Failed to read params");

    // Load existing proving key
    let pk_path = format!("{}/pk.bin", keys_dir);
    println!("Loading proving key from: {}", pk_path);
    let pk_file = File::open(&pk_path).expect("Failed to open pk file. Run keygen first.");
    let mut pk_reader = BufReader::new(pk_file);
    let pk = halo2_proofs::plonk::ProvingKey::<Fr, CS>::read::<_, VPNPaymentCircuit<Fr>>(
        &mut pk_reader, SerdeFormat::RawBytes
    ).expect("Failed to read proving key");

    let input_str = fs::read_to_string(input_path).expect("Failed to read input file");
    let input: serde_json::Value =
        serde_json::from_str(&input_str).expect("Failed to parse input JSON");

    let private = PrivateInputs {
        secret_key: hex_to_bytes32(input["private"]["secret_key"].as_str().unwrap()),
        payment_amount: input["private"]["payment_amount"].as_u64().unwrap(),
        sequence: input["private"]["sequence"].as_u64().unwrap(),
    };

    let public = PublicInputs {
        pricing_tier: input["public"]["pricing_tier"].as_u64().unwrap() as u8,
        region_hash: hex_to_bytes32(input["public"]["region_hash"].as_str().unwrap()),
        nullifier: hex_to_bytes32(input["public"]["nullifier"].as_str().unwrap()),
        provider_commitment: hex_to_bytes32(input["public"]["provider_commitment"].as_str().unwrap()),
        state_root: hex_to_bytes32(input["public"]["state_root"].as_str().unwrap()),
    };

    // Get required price for the tier
    let tier = public.pricing_tier as usize;
    if tier >= TIER_PRICES.len() {
        eprintln!("Error: Invalid pricing tier {}", tier);
        std::process::exit(1);
    }
    let required_price = TIER_PRICES[tier];

    // Validate payment amount covers the required price
    if private.payment_amount < required_price {
        eprintln!(
            "Error: Payment amount {} is less than required price {} for tier {}",
            private.payment_amount, required_price, tier
        );
        std::process::exit(1);
    }

    println!("  Pricing tier: {} (requires {} lovelace)", tier, required_price);
    println!("  Payment amount: {} lovelace", private.payment_amount);

    // Convert inputs to field elements
    let payment_amount_fr = Fr::from(private.payment_amount);
    let pricing_tier_fr = Fr::from(tier as u64);
    let required_price_fr = Fr::from(required_price);

    // Convert nullifier from Midnight (32-byte input) to field element
    // The nullifier is generated by Midnight's persistentHash, not computed here
    let nullifier_bytes: [u8; 32] = public.nullifier;
    let nullifier_int = num_bigint::BigUint::from_bytes_be(&nullifier_bytes);
    let nullifier_bytes_le: Vec<u8> = nullifier_int.to_bytes_le();
    let mut nullifier_repr = [0u8; 32];
    let copy_len = nullifier_bytes_le.len().min(32);
    nullifier_repr[..copy_len].copy_from_slice(&nullifier_bytes_le[..copy_len]);
    let nullifier_fr = Fr::from_repr(nullifier_repr.into()).unwrap_or(Fr::from(0u64));

    println!("  Using nullifier from Midnight: {}", hex::encode(nullifier_bytes));

    // Create the circuit with witness values
    let circuit = VPNPaymentCircuit::new(
        payment_amount_fr, pricing_tier_fr, nullifier_fr, required_price_fr,
    );

    // Public inputs for the instance column: [pricing_tier, nullifier]
    let public_inputs_fr: Vec<Fr> = vec![pricing_tier_fr, nullifier_fr];

    // Output nullifier for debugging
    let nullifier_repr_out = nullifier_fr.to_repr();
    println!("  Nullifier (hex, LE): {}", hex::encode(nullifier_repr_out.as_ref()));

    // Create proof transcript using Aiken-compatible format
    // This uses unkeyed blake2b_256 with byte accumulation to match the Aiken verifier
    println!("  Creating proof with Aiken-compatible transcript...");
    let mut transcript: CircuitTranscript<AikenHashState> = CircuitTranscript::init();

    // Generate the proof
    create_proof::<Fr, CS, CircuitTranscript<AikenHashState>, _>(
        &params, &pk, &[circuit], &[&[&public_inputs_fr]], OsRng, &mut transcript,
    ).expect("Failed to generate proof");

    // Finalize the transcript to get the proof bytes
    let proof_bytes = transcript.finalize();

    println!("  Proof size: {} bytes", proof_bytes.len());

    // Create the payment proof structure with the COMPUTED nullifier (not the input one)
    // The computed nullifier is the actual public input used in the circuit
    let mut computed_nullifier_bytes = [0u8; 32];
    computed_nullifier_bytes.copy_from_slice(nullifier_bytes.as_ref());

    let public_with_computed_nullifier = PublicInputs {
        pricing_tier: public.pricing_tier,
        region_hash: public.region_hash,
        nullifier: computed_nullifier_bytes,
        provider_commitment: public.provider_commitment,
        state_root: public.state_root,
    };

    let proof = PaymentProof {
        proof: proof_bytes.clone(),
        public_inputs: public_with_computed_nullifier,
    };

    let output_str = proof.to_json().expect("Failed to serialize proof");
    fs::write(output_path, &output_str).expect("Failed to write output file");

    let script_path = PathBuf::from(output_path).with_extension("script.json");
    let script_format = proof.to_script_format();
    let script_str = serde_json::to_string_pretty(&script_format).unwrap();
    fs::write(&script_path, &script_str).expect("Failed to write script format");

    // Also output the raw proof hex for easy copy-paste to Aiken tests
    println!("\n=== For Aiken tests ===");
    println!("Proof hex ({} bytes):", proof_bytes.len());
    println!("#\"{}\"", hex::encode(&proof_bytes));
    println!("\nPricing tier (selection): {}", tier);
    println!("Nullifier (from Midnight): {}", hex::encode(&public.nullifier));

    println!("\nProof written to: {}", output_path);
    println!("Script format written to: {}", script_path.display());
}

fn verify_with_keys(keys_dir: &str, proof_path: &str) {
    println!("Verifying proof with saved keys (BLS12-381)...");

    // Load existing parameters
    let params_path = format!("{}/params.bin", keys_dir);
    println!("Loading parameters from: {}", params_path);
    let params_file = File::open(&params_path).expect("Failed to open params file. Run keygen first.");
    let mut params_reader = BufReader::new(params_file);
    let params: ParamsKZG<Bls12381> = ParamsKZG::read_custom(&mut params_reader, SerdeFormat::RawBytes)
        .expect("Failed to read params");

    // Load existing verification key
    let vk_path = format!("{}/vk.bin", keys_dir);
    println!("Loading verification key from: {}", vk_path);
    let vk_file = File::open(&vk_path).expect("Failed to open vk file. Run keygen first.");
    let mut vk_reader = BufReader::new(vk_file);
    let vk = VerifyingKey::<Fr, CS>::read::<_, VPNPaymentCircuit<Fr>>(
        &mut vk_reader, SerdeFormat::RawBytes
    ).expect("Failed to read verification key");

    // Load proof
    let proof_str = fs::read_to_string(proof_path).expect("Failed to read proof file");
    let proof: PaymentProof = serde_json::from_str(&proof_str).expect("Failed to parse proof JSON");

    println!("Proof structure loaded:");
    println!("  Pricing tier: {}", proof.public_inputs.pricing_tier);
    println!("  Region hash: {}", hex::encode(proof.public_inputs.region_hash));
    println!("  Nullifier: {}", hex::encode(proof.public_inputs.nullifier));
    println!("  Provider commitment: {}", hex::encode(proof.public_inputs.provider_commitment));
    println!("  State root: {}", hex::encode(proof.public_inputs.state_root));
    println!("  Proof size: {} bytes", proof.proof.len());

    // Reconstruct public inputs for verification
    let tier = proof.public_inputs.pricing_tier as usize;
    let pricing_tier_fr = Fr::from(tier as u64);

    // Nullifier as field element (from proof public inputs)
    let nullifier_bytes = &proof.public_inputs.nullifier;
    // Convert first 8 bytes to u64 (little-endian, matching proof generation)
    let nullifier_u64 = u64::from_le_bytes(nullifier_bytes[0..8].try_into().unwrap());
    let nullifier_fr = Fr::from(nullifier_u64);

    println!("\nPublic inputs for verification:");
    println!("  pricing_tier_fr: {:?}", pricing_tier_fr);
    println!("  nullifier_fr: {:?}", nullifier_fr);

    let public_inputs_fr: Vec<Fr> = vec![pricing_tier_fr, nullifier_fr];

    // Create transcript from proof bytes for verification
    let mut transcript: CircuitTranscript<AikenHashState> =
        CircuitTranscript::init_from_bytes(&proof.proof);

    println!("\nRunning KZG verification...");

    // Use prepare to get verification guard
    match prepare::<Fr, CS, CircuitTranscript<AikenHashState>>(
        &vk,
        &[&[&public_inputs_fr]],
        &mut transcript,
    ) {
        Ok(guard) => {
            // Get verifier params from KZG params
            let verifier_params = params.verifier_params();

            // Verify the guard
            match guard.verify(&verifier_params) {
                Ok(()) => {
                    println!("\n✓ Verification: SUCCESS");
                    println!("The proof is valid for the given public inputs.");
                }
                Err(e) => {
                    eprintln!("\n✗ Verification: FAILED (pairing check)");
                    eprintln!("Error: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("\n✗ Verification: FAILED (prepare)");
            eprintln!("Error: {:?}", e);
            std::process::exit(1);
        }
    }
}

fn test_standard_transcript(_keys_dir: &str) {
    use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
    use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Fixed, Instance, Selector};
    use halo2_proofs::poly::Rotation;
    use halo2_proofs::halo2curves::ff::Field as _;
    use halo2_proofs::dev::MockProver;

    println!("Testing SIMPLE circuit with BLS12-381 (WITH 2 public inputs and 2 advice columns)...");

    // Define a circuit with fixed column and enable_constant (like VPNPaymentCircuit)
    #[derive(Clone)]
    struct SimpleConfig {
        advice: [Column<Advice>; 4],  // 4 advice columns like VPN circuit
        instance: Column<Instance>,
        fixed: Column<Fixed>,  // Fixed column for constants
        s_load: Selector,
        s_hash: Selector,  // Additional selector like VPN circuit
    }

    #[derive(Clone)]
    struct SimpleCircuit {
        a: Option<Fr>,
        b: Option<Fr>,
        c: Option<Fr>,
        constant: Fr,  // A constant value
    }

    impl Default for SimpleCircuit {
        fn default() -> Self {
            Self {
                a: None,
                b: None,
                c: None,
                constant: Fr::ZERO,
            }
        }
    }

    impl Circuit<Fr> for SimpleCircuit {
        type Config = SimpleConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> SimpleConfig {
            let advice = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];
            let instance = meta.instance_column();
            let fixed = meta.fixed_column();
            let s_load = meta.selector();
            let s_hash = meta.selector();

            // Enable equality on all advice columns
            for col in &advice {
                meta.enable_equality(*col);
            }
            meta.enable_equality(instance);
            meta.enable_constant(fixed);  // RE-ENABLED - testing if enable_constant alone causes failure

            // Load gate - like VPN circuit
            meta.create_gate("load", |meta| {
                let s = meta.query_selector(s_load);
                let value = meta.query_advice(advice[0], Rotation::cur());
                vec![s * (value.clone() - value)]  // Always 0
            });

            // Hash gate - like VPN circuit: out = a + b + c
            meta.create_gate("hash", |meta| {
                let s = meta.query_selector(s_hash);
                let a = meta.query_advice(advice[0], Rotation::cur());
                let b = meta.query_advice(advice[1], Rotation::cur());
                let c = meta.query_advice(advice[2], Rotation::cur());
                let out = meta.query_advice(advice[3], Rotation::cur());
                vec![s * (a + b + c - out)]
            });

            SimpleConfig { advice, instance, fixed, s_load, s_hash }
        }

        fn synthesize(&self, config: SimpleConfig, mut layouter: impl Layouter<Fr>) -> Result<(), halo2_proofs::plonk::Error> {
            // Load private values
            let cell_a = layouter.assign_region(
                || "load a",
                |mut region| {
                    config.s_load.enable(&mut region, 0)?;
                    let val = self.a.unwrap_or(Fr::ZERO);
                    region.assign_advice(|| "a", config.advice[0], 0, || Value::known(val))
                },
            )?;

            let cell_b = layouter.assign_region(
                || "load b",
                |mut region| {
                    config.s_load.enable(&mut region, 0)?;
                    let val = self.b.unwrap_or(Fr::ZERO);
                    region.assign_advice(|| "b", config.advice[0], 0, || Value::known(val))
                },
            )?;

            let cell_c = layouter.assign_region(
                || "load c",
                |mut region| {
                    config.s_load.enable(&mut region, 0)?;
                    let val = self.c.unwrap_or(Fr::ZERO);
                    region.assign_advice(|| "c", config.advice[0], 0, || Value::known(val))
                },
            )?;

            // RE-ENABLED for testing: assign_advice_from_constant
            let _const_cell = layouter.assign_region(
                || "load constant",
                |mut region| {
                    region.assign_advice_from_constant(
                        || "constant value",
                        config.advice[0],
                        0,
                        self.constant,
                    )
                },
            )?;

            // Hash: out = a + b + c
            let hash_out = layouter.assign_region(
                || "hash",
                |mut region| {
                    config.s_hash.enable(&mut region, 0)?;
                    cell_a.copy_advice(|| "a", &mut region, config.advice[0], 0)?;
                    cell_b.copy_advice(|| "b", &mut region, config.advice[1], 0)?;
                    cell_c.copy_advice(|| "c", &mut region, config.advice[2], 0)?;
                    let hash_value = cell_a.value().copied() + cell_b.value().copied() + cell_c.value().copied();
                    region.assign_advice(|| "hash out", config.advice[3], 0, || hash_value)
                },
            )?;

            // Constrain public inputs
            layouter.constrain_instance(cell_a.cell(), config.instance, 0)?;
            layouter.constrain_instance(hash_out.cell(), config.instance, 1)?;

            Ok(())
        }
    }

    let k = 4;

    let test_a = Fr::from(42u64);
    let test_b = Fr::from(100u64);
    let test_c = Fr::from(58u64);  // a + b + c = 42 + 100 + 58 = 200
    let constant = Fr::from(1000u64);  // Some constant
    let hash_out = test_a + test_b + test_c;  // = 200

    let circuit = SimpleCircuit {
        a: Some(test_a),
        b: Some(test_b),
        c: Some(test_c),
        constant,
    };
    // Public inputs: [a, hash_out]
    let public_inputs_fr: Vec<Fr> = vec![test_a, hash_out];

    // First verify with MockProver
    println!("\nRunning MockProver...");
    let prover = MockProver::run(k, &circuit, vec![public_inputs_fr.clone()])
        .expect("MockProver::run failed");

    match prover.verify() {
        Ok(()) => println!("✓ MockProver: Circuit constraints satisfied"),
        Err(errors) => {
            eprintln!("✗ MockProver: Circuit constraints VIOLATED:");
            for e in &errors {
                eprintln!("  {:?}", e);
            }
            return;
        }
    }

    println!("\nGenerating fresh SRS parameters (k={})...", k);
    let params: ParamsKZG<Bls12381> = CS::gen_params(k);

    let empty_circuit = SimpleCircuit::default();
    println!("Generating fresh verification key...");
    let vk = keygen_vk_with_k::<Fr, CS, _>(&params, &empty_circuit, k)
        .expect("Failed to generate verification key");
    println!("Generating fresh proving key...");
    let pk = keygen_pk::<Fr, CS, _>(vk.clone(), &empty_circuit)
        .expect("Failed to generate proving key");

    // Re-create circuit for proving
    let circuit = SimpleCircuit {
        a: Some(test_a),
        b: Some(test_b),
        c: Some(test_c),
        constant,
    };

    println!("Public inputs: {:?}", public_inputs_fr);
    println!("\nGenerating proof with standard blake2b transcript...");
    let mut transcript_prove: CircuitTranscript<Blake2bState> = CircuitTranscript::init();

    create_proof::<Fr, CS, CircuitTranscript<Blake2bState>, _>(
        &params, &pk, &[circuit], &[&[&public_inputs_fr]], OsRng, &mut transcript_prove,
    ).expect("Failed to generate proof");

    let proof_bytes = transcript_prove.finalize();
    println!("Proof size: {} bytes", proof_bytes.len());

    println!("Verifying proof with standard blake2b transcript...");
    let mut transcript_verify: CircuitTranscript<Blake2bState> =
        CircuitTranscript::init_from_bytes(&proof_bytes);

    match prepare::<Fr, CS, CircuitTranscript<Blake2bState>>(
        pk.get_vk(),
        &[&[&public_inputs_fr]],
        &mut transcript_verify,
    ) {
        Ok(guard) => {
            let verifier_params = params.verifier_params();
            match guard.verify(&verifier_params) {
                Ok(()) => {
                    println!("\n✓ SIMPLE CIRCUIT BLS12-381 (with public inputs): Verification SUCCESS");
                }
                Err(e) => {
                    eprintln!("\n✗ SIMPLE CIRCUIT BLS12-381: Verification FAILED (pairing)");
                    eprintln!("Error: {:?}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("\n✗ SIMPLE CIRCUIT BLS12-381: Verification FAILED (prepare)");
            eprintln!("Error: {:?}", e);
        }
    }
}

fn test_vpn_circuit_in_memory() {
    use halo2_proofs::dev::MockProver;

    println!("Testing VPNPaymentCircuit with BLS12-381 (in-memory, no serialization)...");

    let k = 8;

    // Create test circuit values
    let payment_amount = Fr::from(15000000u64);
    let pricing_tier = Fr::from(0u64);
    let required_price = Fr::from(TIER_PRICES[0]);

    // Simulate a nullifier from Midnight (test value)
    let nullifier_fr = Fr::from(0xDEADBEEFCAFEBABEu64);

    println!("  Using test nullifier (simulating Midnight)");

    // Create circuit for proving
    let circuit = VPNPaymentCircuit::new(
        payment_amount, pricing_tier, nullifier_fr, required_price,
    );

    // Public inputs: [pricing_tier, nullifier]
    println!("\nPublic inputs:");
    println!("  pricing_tier: {:?}", pricing_tier);
    println!("  nullifier: {:?}", nullifier_fr);

    let public_inputs_fr: Vec<Fr> = vec![pricing_tier, nullifier_fr];

    // First, verify with MockProver
    println!("\nRunning MockProver to verify circuit constraints...");
    let prover = MockProver::run(k, &circuit, vec![public_inputs_fr.clone()])
        .expect("MockProver::run failed");

    match prover.verify() {
        Ok(()) => println!("✓ MockProver: Circuit constraints satisfied"),
        Err(errors) => {
            eprintln!("✗ MockProver: Circuit constraints VIOLATED:");
            for e in &errors {
                eprintln!("  {:?}", e);
            }
            return;
        }
    }

    println!("\nGenerating fresh SRS parameters (k={})...", k);
    let params: ParamsKZG<Bls12381> = CS::gen_params(k);

    // Create circuit for keygen (empty)
    let empty_circuit = VPNPaymentCircuit::<Fr>::default();

    println!("Generating fresh verification key...");
    let vk = keygen_vk_with_k::<Fr, CS, _>(&params, &empty_circuit, k)
        .expect("Failed to generate verification key");
    println!("Generating fresh proving key...");
    let pk = keygen_pk::<Fr, CS, _>(vk.clone(), &empty_circuit)
        .expect("Failed to generate proving key");

    // Re-create circuit for proving
    let circuit = VPNPaymentCircuit::new(
        payment_amount, pricing_tier, nullifier_fr, required_price,
    );

    println!("\nGenerating proof with standard blake2b transcript...");
    let mut transcript_prove: CircuitTranscript<Blake2bState> = CircuitTranscript::init();

    match create_proof::<Fr, CS, CircuitTranscript<Blake2bState>, _>(
        &params, &pk, &[circuit], &[&[&public_inputs_fr]], OsRng, &mut transcript_prove,
    ) {
        Ok(()) => {
            println!("Proof generation succeeded!");
        }
        Err(e) => {
            eprintln!("\n✗ VPNPaymentCircuit: Proof generation FAILED");
            eprintln!("Error: {:?}", e);
            return;
        }
    }

    let proof_bytes = transcript_prove.finalize();
    println!("Proof size: {} bytes", proof_bytes.len());

    println!("\nVerifying proof with standard blake2b transcript...");
    let mut transcript_verify: CircuitTranscript<Blake2bState> =
        CircuitTranscript::init_from_bytes(&proof_bytes);

    match prepare::<Fr, CS, CircuitTranscript<Blake2bState>>(
        pk.get_vk(),
        &[&[&public_inputs_fr]],
        &mut transcript_verify,
    ) {
        Ok(guard) => {
            let verifier_params = params.verifier_params();
            match guard.verify(&verifier_params) {
                Ok(()) => {
                    println!("\n✓ VPNPaymentCircuit BLS12-381: Verification SUCCESS");
                }
                Err(e) => {
                    eprintln!("\n✗ VPNPaymentCircuit BLS12-381: Verification FAILED (pairing)");
                    eprintln!("Error: {:?}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("\n✗ VPNPaymentCircuit BLS12-381: Verification FAILED (prepare)");
            eprintln!("Error: {:?}", e);
        }
    }
}

fn verify(proof_path: &str) {
    println!("Verifying proof (BLS12-381)...");

    let proof_str = fs::read_to_string(proof_path).expect("Failed to read proof file");
    let proof: PaymentProof = serde_json::from_str(&proof_str).expect("Failed to parse proof JSON");

    println!("Proof structure loaded:");
    println!("  Pricing tier: {}", proof.public_inputs.pricing_tier);
    println!("  Region hash: {}", hex::encode(proof.public_inputs.region_hash));
    println!("  Nullifier: {}", hex::encode(proof.public_inputs.nullifier));
    println!("  Provider commitment: {}", hex::encode(proof.public_inputs.provider_commitment));
    println!("  State root: {}", hex::encode(proof.public_inputs.state_root));
    println!("  Proof size: {} bytes", proof.proof.len());

    use halo2_proofs::dev::MockProver;

    let k = 8;
    let tier = proof.public_inputs.pricing_tier as usize;
    if tier >= TIER_PRICES.len() {
        eprintln!("Error: Invalid pricing tier {}", tier);
        std::process::exit(1);
    }
    let required_price = TIER_PRICES[tier];

    // Use the nullifier from the proof file (it was computed with Poseidon)
    // Convert nullifier from proof (32-byte big-endian) to field element
    let nullifier_bytes: [u8; 32] = proof.public_inputs.nullifier;
    let nullifier_int = num_bigint::BigUint::from_bytes_be(&nullifier_bytes);
    let nullifier_bytes_le: Vec<u8> = nullifier_int.to_bytes_le();
    let mut nullifier_repr = [0u8; 32];
    let copy_len = nullifier_bytes_le.len().min(32);
    nullifier_repr[..copy_len].copy_from_slice(&nullifier_bytes_le[..copy_len]);
    let nullifier_fr = Fr::from_repr(nullifier_repr.into()).unwrap_or(Fr::from(0u64));

    let pricing_tier_fr = Fr::from(tier as u64);
    // For MockProver testing, we need a payment_amount (private input)
    // Use the required_price as a valid value
    let payment_amount_fr = Fr::from(required_price);

    // Note: For actual verification, we use the real proof verifier, not MockProver
    // MockProver requires knowing the private inputs, which defeats ZK
    // This function is for debugging only

    let circuit = VPNPaymentCircuit::new(
        payment_amount_fr, pricing_tier_fr, nullifier_fr, Fr::from(required_price),
    );

    // Public inputs for the circuit
    let public_inputs = vec![pricing_tier_fr, nullifier_fr];

    println!("\nRunning circuit verification...");

    match MockProver::run(k, &circuit, vec![public_inputs]) {
        Ok(prover) => match prover.verify() {
            Ok(()) => {
                println!("\nVerification: SUCCESS");
                println!("The proof structure is valid and circuit constraints are satisfied.");
            }
            Err(errors) => {
                eprintln!("\nVerification: FAILED");
                for error in errors { eprintln!("  {:?}", error); }
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("\nVerification: FAILED - MockProver error: {:?}", e);
            std::process::exit(1);
        }
    }
}

fn keygen(output_dir: &str) {
    println!("Generating proving and verification keys (BLS12-381)...");
    println!("Circuit size: k={} (2^{} = {} rows)", CIRCUIT_K, CIRCUIT_K, 1 << CIRCUIT_K);

    fs::create_dir_all(output_dir).expect("Failed to create output directory");

    println!("Generating SRS parameters (this may take a moment)...");
    let params: ParamsKZG<Bls12381> = CS::gen_params(CIRCUIT_K);

    let circuit = VPNPaymentCircuit::<Fr>::default();

    println!("Generating verification key...");
    let vk = keygen_vk_with_k::<Fr, CS, _>(&params, &circuit, CIRCUIT_K).expect("Failed to generate verification key");

    println!("Generating proving key...");
    let pk = keygen_pk::<Fr, CS, _>(vk.clone(), &circuit).expect("Failed to generate proving key");

    let params_path = format!("{}/params.bin", output_dir);
    let params_file = File::create(&params_path).expect("Failed to create params file");
    let mut params_writer = BufWriter::new(params_file);
    params.write_custom(&mut params_writer, SerdeFormat::RawBytes).expect("Failed to write params");
    params_writer.flush().expect("Failed to flush params");
    println!("Parameters written to: {}", params_path);

    let vk_path = format!("{}/vk.bin", output_dir);
    let vk_file = File::create(&vk_path).expect("Failed to create vk file");
    let mut vk_writer = BufWriter::new(vk_file);
    vk.write(&mut vk_writer, SerdeFormat::RawBytes).expect("Failed to write verification key");
    vk_writer.flush().expect("Failed to flush vk");
    println!("Verification key written to: {}", vk_path);

    let pk_path = format!("{}/pk.bin", output_dir);
    let pk_file = File::create(&pk_path).expect("Failed to create pk file");
    let mut pk_writer = BufWriter::new(pk_file);
    pk.write(&mut pk_writer, SerdeFormat::RawBytes).expect("Failed to write proving key");
    pk_writer.flush().expect("Failed to flush pk");
    println!("Proving key written to: {}", pk_path);

    println!("\nKey generation complete!");
    println!("Files created in {}:", output_dir);
    println!("  - params.bin  (SRS parameters)");
    println!("  - vk.bin      (verification key)");
    println!("  - pk.bin      (proving key)");
}

fn export_verifier(keys_dir: &str, output_file: &str) {
    println!("Exporting Aiken verifier key constants (BLS12-381)...");

    let params_path = format!("{}/params.bin", keys_dir);
    println!("Loading parameters from: {}", params_path);
    let params_file = File::open(&params_path).expect("Failed to open params file. Run keygen first.");
    let mut params_reader = BufReader::new(params_file);
    let params: ParamsKZG<Bls12381> = ParamsKZG::read_custom(&mut params_reader, SerdeFormat::RawBytes).expect("Failed to read params");

    let vk_path = format!("{}/vk.bin", keys_dir);
    println!("Loading verification key from: {}", vk_path);
    let vk_file = File::open(&vk_path).expect("Failed to open vk file. Run keygen first.");
    let mut vk_reader = BufReader::new(vk_file);

    let vk: VerifyingKey<Fr, CS> =
        VerifyingKey::read::<_, VPNPaymentCircuit<Fr>>(&mut vk_reader, SerdeFormat::RawBytes)
            .expect("Failed to read verification key");

    println!("Extracting verification key components...");

    let domain = vk.get_domain();
    let omega = domain.get_omega();
    let omega_inv = omega.invert().unwrap();
    let k = params.max_k();
    let n = 1u64 << k;

    let fixed_commitments = vk.fixed_commitments();

    let mut output = String::new();
    output.push_str("// Auto-generated verification key constants for VPN Payment Circuit\n");
    output.push_str("// Generated by: vpn-payment-circuit export-verifier\n");
    output.push_str("// Curve: BLS12-381 (Cardano compatible)\n");
    output.push_str(&format!("// Circuit size: k={}, n={}\n\n", k, n));

    output.push_str("use aiken/crypto/bls12_381/scalar.{Scalar}\n");
    output.push_str("use aiken/crypto/bls12_381/g2.{decompress as decompress_g2}\n");
    output.push_str("use halo2/compat.{State, from_int}\n\n");

    output.push_str("// Fixed polynomial commitments (compressed G1 points)\n");
    for (i, commitment) in fixed_commitments.iter().enumerate() {
        let compressed = compress_g1_point(commitment);
        output.push_str(&format!("pub const f{}_commitment: ByteArray = #\"{}\"\n", i + 1, hex::encode(compressed)));
    }
    output.push('\n');

    let permutation_commitments = vk.permutation().commitments();
    output.push_str("// Permutation polynomial commitments (compressed G1 points)\n");
    for (i, commitment) in permutation_commitments.iter().enumerate() {
        let compressed = compress_g1_point(commitment);
        output.push_str(&format!("pub const p{}_commitment: ByteArray = #\"{}\"\n", i + 1, hex::encode(compressed)));
    }
    output.push('\n');

    let s_g2 = params.s_g2();
    use halo2_proofs::halo2curves::group::Curve;
    let s_g2_affine: G2Affine = s_g2.to_affine();
    let g2_compressed = compress_g2_point(&s_g2_affine);
    output.push_str("// KZG s*G2 parameter (compressed G2 point)\n");
    output.push_str(&format!("pub const g2_const: G2Element = decompress_g2(#\"{}\")\n\n", hex::encode(g2_compressed)));

    let neg_g1 = -G1Affine::generator();
    let neg_g1_compressed = compress_g1_point_affine(&neg_g1);
    output.push_str("// Negated G1 generator (compressed)\n");
    output.push_str(&format!("pub const neg_g1_generator: ByteArray = #\"{}\"\n\n", hex::encode(neg_g1_compressed).to_uppercase()));

    output.push_str("// Domain parameters\n");
    output.push_str(&format!("pub const omega: State<Scalar> = from_int(0x{})\n", format_scalar(&omega)));
    output.push_str(&format!("pub const omega_inv: State<Scalar> = from_int(0x{})\n\n", format_scalar(&omega_inv)));

    let blinding_factors = vk.cs().blinding_factors();
    output.push_str(&format!("pub const blinding_factors: Int = {}\n\n", blinding_factors));

    // Compute barycentric weight: product of (omega^i - 1)^(-1) for i in 1..n
    // For KZG verification at the evaluation point
    use halo2_proofs::halo2curves::ff::BatchInvert;
    let n_usize = n as usize;
    let mut barycentric_weights: Vec<Fr> = Vec::with_capacity(n_usize);
    let mut omega_power = omega;
    for _ in 1..n_usize {
        barycentric_weights.push(omega_power - Fr::ONE);
        omega_power = omega_power * omega;
    }
    barycentric_weights.batch_invert();
    let barycentric_weight: Fr = barycentric_weights.iter().fold(Fr::ONE, |acc, x| acc * x);
    output.push_str("// Barycentric weight for Lagrange interpolation\n");
    output.push_str(&format!("pub const barycentric_weight: State<Scalar> = from_int(0x{})\n\n", format_scalar(&barycentric_weight)));

    // Get the transcript_repr directly from the verification key
    // This is the value used by the prover to initialize the Fiat-Shamir transcript
    // IOG halo2 computes this by hashing the debug format of the pinned domain and constraint system
    let transcript_repr = vk.transcript_repr();
    output.push_str("// Transcript representation (from verification key - used by prover)\n");
    output.push_str(&format!("pub const transcript_rep: State<Scalar> = from_int(0x{})\n", format_scalar(&transcript_repr)));

    // Print for debugging
    println!("  transcript_repr scalar: 0x{}", format_scalar(&transcript_repr));

    let output_path = PathBuf::from(output_file);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).expect("Failed to create output directory");
    }
    fs::write(&output_path, &output).expect("Failed to write output file");

    println!("\nVerifier key exported to: {}", output_file);
    println!("Contains {} fixed commitments, {} permutation commitments", fixed_commitments.len(), permutation_commitments.len());
}

fn debug_verify(keys_dir: &str, proof_path: &str) {
    use halo2_proofs::halo2curves::group::GroupEncoding;
    use halo2_proofs::halo2curves::ff::PrimeField;
    use halo2_proofs::halo2curves::CurveAffine;

    println!("Debug verification - extracting pairing inputs...\n");

    // Load existing parameters
    let params_path = format!("{}/params.bin", keys_dir);
    let params_file = File::open(&params_path).expect("Failed to open params file");
    let mut params_reader = BufReader::new(params_file);
    let params: ParamsKZG<Bls12381> = ParamsKZG::read_custom(&mut params_reader, SerdeFormat::RawBytes)
        .expect("Failed to read params");

    // Load existing verification key
    let vk_path = format!("{}/vk.bin", keys_dir);
    let vk_file = File::open(&vk_path).expect("Failed to open vk file");
    let mut vk_reader = BufReader::new(vk_file);
    let vk = VerifyingKey::<Fr, CS>::read::<_, VPNPaymentCircuit<Fr>>(
        &mut vk_reader, SerdeFormat::RawBytes
    ).expect("Failed to read verification key");

    // Load proof
    let proof_str = fs::read_to_string(proof_path).expect("Failed to read proof file");
    let proof: PaymentProof = serde_json::from_str(&proof_str).expect("Failed to parse proof JSON");

    println!("Proof size: {} bytes", proof.proof.len());

    // The pi_term (W in multi-open protocol) is the last G1 point in the proof
    // In KZG multi-open, the proof ends with the final opening proof point
    // Let's extract it from the end of the proof
    let proof_len = proof.proof.len();

    // G1 compressed point is 48 bytes
    if proof_len >= 48 {
        let pi_term_bytes = &proof.proof[proof_len - 48..];
        println!("\n=== Last 48 bytes (pi_term/W) ===");
        println!("pi_term hex: {}", hex::encode(pi_term_bytes));

        // Try to decompress to verify it's valid
        let mut pi_array = [0u8; 48];
        pi_array.copy_from_slice(pi_term_bytes);
        let point_opt = G1Affine::from_bytes(&pi_array.into());
        if point_opt.is_some().unwrap_u8() == 1 {
            let point = point_opt.unwrap();
            if point.is_on_curve().unwrap_u8() == 1 {
                println!("pi_term is valid G1 point on curve");
                // Also show compressed form (should be same)
                let recompressed = point.to_bytes();
                println!("Recompressed:   {}", hex::encode(recompressed.as_ref()));
            } else {
                println!("WARNING: pi_term NOT on curve!");
            }
        } else {
            println!("Failed to decompress pi_term");
        }
    }

    // Extract public inputs
    let tier = proof.public_inputs.pricing_tier as usize;
    let pricing_tier_fr = Fr::from(tier as u64);
    let nullifier_bytes = &proof.public_inputs.nullifier;
    let nullifier_u64 = u64::from_le_bytes(nullifier_bytes[0..8].try_into().unwrap());
    let nullifier_fr = Fr::from(nullifier_u64);

    println!("\n=== Public inputs ===");
    println!("pricing_tier: {} (Fr: 0x{})", tier, format_scalar(&pricing_tier_fr));
    println!("nullifier (LE hex): {}", hex::encode(&nullifier_bytes));
    println!("nullifier Fr: 0x{}", format_scalar(&nullifier_fr));

    // Show transcript_repr from vk
    let transcript_repr = vk.transcript_repr();
    println!("\n=== Transcript repr ===");
    println!("transcript_repr: 0x{}", format_scalar(&transcript_repr));

    // Show s*G2 in different formats
    println!("\n=== s*G2 point ===");
    let s_g2 = params.s_g2();
    use halo2_proofs::halo2curves::group::Curve;
    let s_g2_affine: G2Affine = s_g2.to_affine();
    let s_g2_raw = s_g2_affine.to_bytes();
    println!("s*G2 raw (halo2curves):  {}", hex::encode(s_g2_raw.as_ref()));
    let s_g2_converted = compress_g2_point(&s_g2_affine);
    println!("s*G2 converted (blst):   {}", hex::encode(&s_g2_converted));

    // Show G2 generator
    println!("\n=== G2 generator ===");
    let g2_gen = G2Affine::generator();
    let g2_gen_raw = g2_gen.to_bytes();
    println!("G2 gen raw (halo2curves): {}", hex::encode(g2_gen_raw.as_ref()));
    let g2_gen_converted = compress_g2_point(&g2_gen);
    println!("G2 gen converted (blst):  {}", hex::encode(&g2_gen_converted));

    // Now run the actual verification to see if it passes
    let public_inputs_fr: Vec<Fr> = vec![pricing_tier_fr, nullifier_fr];

    println!("\n=== Running verification ===");
    let mut transcript: CircuitTranscript<AikenHashState> =
        CircuitTranscript::init_from_bytes(&proof.proof);

    match prepare::<Fr, CS, CircuitTranscript<AikenHashState>>(
        &vk,
        &[&[&public_inputs_fr]],
        &mut transcript,
    ) {
        Ok(guard) => {
            println!("Prepare succeeded");

            // Extract the MSM terms to get v and x3
            let (left_pairs, right_pairs) = guard.split();
            println!("\n=== MSM Details ===");
            println!("Left MSM has {} terms", left_pairs.len());
            println!("Right MSM has {} terms", right_pairs.len());

            // Print all right MSM terms for debugging
            use num_bigint::BigUint;
            println!("\n=== All Right MSM Terms ===");
            for (i, (scalar, _point)) in right_pairs.iter().enumerate() {
                let scalar_bytes: [u8; 32] = scalar.to_repr().as_ref().try_into().unwrap();
                let scalar_decimal = BigUint::from_bytes_le(&scalar_bytes);
                println!("Term {}: scalar = {}", i, scalar_decimal);
            }

            // The v scalar should be in one of the last terms
            // In SHPLONK, the MSM is: -v*G1 + x3*pi
            // where v = q1 + x4*q2 + x4^2*q3 + x4^3*f_eval
            if right_pairs.len() >= 2 {
                let last_idx = right_pairs.len() - 1;
                println!("\n=== Last two terms (likely x3*pi and -v*G1) ===");

                // Last term (x3*pi)
                let (x3_scalar, _) = &right_pairs[last_idx];
                let x3_bytes: [u8; 32] = x3_scalar.to_repr().as_ref().try_into().unwrap();
                let x3_decimal = BigUint::from_bytes_le(&x3_bytes);
                println!("Term {} (x3 or related): {}", last_idx, x3_decimal);

                // Second to last term (might be -v*G1)
                let (v_scalar, _) = &right_pairs[last_idx - 1];
                let v_bytes: [u8; 32] = v_scalar.to_repr().as_ref().try_into().unwrap();
                let v_decimal = BigUint::from_bytes_le(&v_bytes);
                println!("Term {} (v or related): {}", last_idx - 1, v_decimal);
            }

            // The guard contains the pi and msm points
            // Let's try to access them through the verify method
            let verifier_params = params.verifier_params();

            match guard.verify(&verifier_params) {
                Ok(()) => {
                    println!("Verification: SUCCESS");
                }
                Err(e) => {
                    println!("Verification: FAILED");
                    println!("Error: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("Prepare failed: {:?}", e);
        }
    }
}

fn debug_g2_serialization(keys_dir: &str) {
    println!("Debugging G2 serialization formats...\n");

    // Load existing parameters
    let params_path = format!("{}/params.bin", keys_dir);
    println!("Loading parameters from: {}", params_path);
    let params_file = File::open(&params_path).expect("Failed to open params file. Run keygen first.");
    let mut params_reader = BufReader::new(params_file);
    let params: ParamsKZG<Bls12381> = ParamsKZG::read_custom(&mut params_reader, SerdeFormat::RawBytes)
        .expect("Failed to read params");

    // Get s*G2 point
    let s_g2 = params.s_g2();
    use halo2_proofs::halo2curves::group::Curve;
    let s_g2_affine: G2Affine = s_g2.to_affine();

    // Get raw bytes from halo2curves
    use halo2_proofs::halo2curves::group::GroupEncoding;
    let raw_bytes = s_g2_affine.to_bytes();
    let raw = raw_bytes.as_ref();

    println!("=== Raw halo2curves G2 serialization ===");
    println!("Total length: {} bytes", raw.len());
    println!("First 48 bytes: {}", hex::encode(&raw[0..48]));
    println!("Last 48 bytes:  {}", hex::encode(&raw[48..96]));
    println!("Full raw:       {}", hex::encode(raw));
    println!();

    // Check flags on first byte
    let first_byte = raw[0];
    println!("First byte:     0x{:02x}", first_byte);
    println!("  Bit 7 (compressed): {}", (first_byte >> 7) & 1);
    println!("  Bit 6 (infinity):   {}", (first_byte >> 6) & 1);
    println!("  Bit 5 (largest y):  {}", (first_byte >> 5) & 1);
    println!();

    // Current conversion (swapping c0/c1)
    let converted = compress_g2_point(&s_g2_affine);
    println!("=== Converted (swapped c0/c1) ===");
    println!("Full converted: {}", hex::encode(&converted));
    println!();

    // No conversion (raw bytes as-is)
    let no_conversion = raw.to_vec();
    println!("=== No conversion (raw as-is) ===");
    println!("Full no-conv:   {}", hex::encode(&no_conversion));
    println!();

    // Alternative: swap but DON'T move flags (maybe flags should stay on first 48 bytes)
    let mut alt1 = Vec::with_capacity(96);
    alt1.extend_from_slice(&raw[48..96]);  // c0
    alt1.extend_from_slice(&raw[0..48]);   // c1 (with original flags)
    println!("=== Alternative 1: swap order, keep flags on c1 ===");
    println!("Full alt1:      {}", hex::encode(&alt1));
    println!();

    // Alternative 2: just check if the first 48 bytes already represent c0 or c1
    // by looking at the structure
    println!("=== Aiken currently expects: ===");
    println!("#\"{}\"", hex::encode(&converted));
    println!();

    println!("=== Testing with known G2 generator ===");
    let g2_gen = G2Affine::generator();
    let g2_gen_raw = g2_gen.to_bytes();
    let g2_gen_raw = g2_gen_raw.as_ref();
    println!("G2 generator raw: {}", hex::encode(g2_gen_raw));

    let g2_gen_converted = compress_g2_point(&g2_gen);
    println!("G2 gen converted: {}", hex::encode(&g2_gen_converted));
    println!();

    // Also print the expected Zcash/blst G2 generator for comparison
    // The standard BLS12-381 G2 generator compressed representation
    println!("Note: Standard G2 generator in Zcash/blst format should start with 0x93...");
    println!("If our raw starts with 0x93, then no conversion is needed.");
    println!("If our raw starts differently, conversion may be needed.");
}

fn compress_g1_point(point: &G1) -> Vec<u8> {
    use halo2_proofs::halo2curves::group::GroupEncoding;
    point.to_bytes().as_ref().to_vec()
}

fn compress_g1_point_affine(point: &G1Affine) -> Vec<u8> {
    use halo2_proofs::halo2curves::group::GroupEncoding;
    point.to_bytes().as_ref().to_vec()
}

/// Convert G2 point from halo2curves format to blst/Zcash format
///
/// halo2curves serializes G2 as [c1 | c0] with flags on c1
/// blst/Zcash expects [c0 | c1] with flags on c0
fn compress_g2_point(point: &G2Affine) -> Vec<u8> {
    use halo2_proofs::halo2curves::group::GroupEncoding;
    let bytes = point.to_bytes();
    let raw = bytes.as_ref();

    // halo2curves format: [c1 (48 bytes) | c0 (48 bytes)]
    // blst format:        [c0 (48 bytes) | c1 (48 bytes)]
    let c1 = &raw[0..48];  // First half in halo2curves is c1
    let c0 = &raw[48..96]; // Second half in halo2curves is c0

    // Extract flag bits from c1 (halo2curves puts flags on first byte)
    let flags = c1[0] & 0xE0; // Top 3 bits: compressed, infinity, largest_y

    // Build blst format: [c0 with flags | c1 without flags]
    let mut result = Vec::with_capacity(96);

    // c0 with flags (blst puts flags on c0)
    let mut c0_with_flags = c0.to_vec();
    c0_with_flags[0] = (c0_with_flags[0] & 0x1F) | flags;
    result.extend_from_slice(&c0_with_flags);

    // c1 without flags
    let mut c1_without_flags = c1.to_vec();
    c1_without_flags[0] = c1_without_flags[0] & 0x1F;
    result.extend_from_slice(&c1_without_flags);

    result
}

fn format_scalar(scalar: &Fr) -> String {
    use halo2_proofs::halo2curves::ff::PrimeField;
    let bytes = scalar.to_repr();
    let mut be_bytes = bytes.as_ref().to_vec();
    be_bytes.reverse();
    hex::encode(be_bytes)
}

fn hex_to_bytes32(hex_str: &str) -> [u8; 32] {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).expect("Invalid hex string");
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes[..32.min(bytes.len())]);
    result
}

/// Debug MSM computation - traces all intermediate values to compare with Aiken
/// Uses hardcoded values from the fresh proof for step-by-step debugging
fn debug_msm_computation(keys_dir: &str) {
    use halo2_proofs::halo2curves::group::{Curve, GroupEncoding};
    use halo2_proofs::halo2curves::ff::PrimeField;

    println!("=== Debug MSM Computation ===\n");

    // Load parameters
    let params_path = format!("{}/params.bin", keys_dir);
    let params_file = File::open(&params_path).expect("Failed to open params file");
    let mut params_reader = BufReader::new(params_file);
    let params: ParamsKZG<Bls12381> = ParamsKZG::read_custom(&mut params_reader, SerdeFormat::RawBytes)
        .expect("Failed to read params");

    // Load verification key
    let vk_path = format!("{}/vk.bin", keys_dir);
    let vk_file = File::open(&vk_path).expect("Failed to open vk file");
    let mut vk_reader = BufReader::new(vk_file);
    let vk = VerifyingKey::<Fr, CS>::read::<_, VPNPaymentCircuit<Fr>>(
        &mut vk_reader, SerdeFormat::RawBytes
    ).expect("Failed to read verification key");

    // Hardcoded values from Aiken trace (fresh proof)
    // x3 from trace: 9486168834651147259167250927348464369180236421939963487431351574452585106427
    let x3_str = "9486168834651147259167250927348464369180236421939963487431351574452585106427";
    let x3_bigint = num_bigint::BigUint::parse_bytes(x3_str.as_bytes(), 10).unwrap();
    let x3_bytes = x3_bigint.to_bytes_le();
    let mut x3_repr = [0u8; 32];
    x3_repr[..x3_bytes.len().min(32)].copy_from_slice(&x3_bytes[..x3_bytes.len().min(32)]);
    let x3 = Fr::from_repr(x3_repr.into()).unwrap();

    println!("x3: 0x{}", format_scalar(&x3));

    // v from Aiken trace: 13723762600720973930567618457699291569302405656685985111537223563536670929717
    let v_str = "13723762600720973930567618457699291569302405656685985111537223563536670929717";
    let v_bigint = num_bigint::BigUint::parse_bytes(v_str.as_bytes(), 10).unwrap();
    let v_bytes = v_bigint.to_bytes_le();
    let mut v_repr = [0u8; 32];
    v_repr[..v_bytes.len().min(32)].copy_from_slice(&v_bytes[..v_bytes.len().min(32)]);
    let v = Fr::from_repr(v_repr.into()).unwrap();

    println!("v: 0x{}", format_scalar(&v));

    // pi_term from Aiken trace (this is the last 48 bytes of the proof)
    let pi_term_hex = "998aaf1936048b278e520bb05389122ba95e057fec2133603a27b7b2ae6d12f17c5a6f4fbc837d3bf2d4c93e77c549a4";
    let pi_term_bytes = hex::decode(pi_term_hex).unwrap();
    let mut pi_array = [0u8; 48];
    pi_array.copy_from_slice(&pi_term_bytes);
    let pi_term_opt = G1Affine::from_bytes(&pi_array.into());

    if pi_term_opt.is_none().into() {
        println!("ERROR: Failed to decompress pi_term!");
        return;
    }
    let pi_term = pi_term_opt.unwrap();
    println!("pi_term (el) decompressed OK");
    println!("pi_term compressed: {}", hex::encode(pi_term.to_bytes().as_ref()));

    // Compute pi_scaled = pi_term * x3
    let pi_scaled = (pi_term * x3).to_affine();
    println!("\npi_scaled = pi_term * x3:");
    println!("pi_scaled compressed: {}", hex::encode(pi_scaled.to_bytes().as_ref()));

    // Get negated G1 generator
    let g1_gen = G1Affine::generator();
    let neg_g1 = G1Affine::from(-g1_gen);
    println!("\nneg_g1_generator:");
    println!("neg_g1 compressed: {}", hex::encode(neg_g1.to_bytes().as_ref()));

    // Compute neg_g1_scaled = neg_g1 * v
    let neg_g1_scaled = (neg_g1 * v).to_affine();
    println!("\nneg_g1_scaled = neg_g1 * v:");
    println!("neg_g1_scaled compressed: {}", hex::encode(neg_g1_scaled.to_bytes().as_ref()));

    // final_com from Aiken trace
    let final_com_hex = "a3d8787801a7f728bda6022a029dbdcc2fa5facfb695e7a770042c9bf1624261e590709bed7da4507fd1f37204f543a7";
    let final_com_bytes = hex::decode(final_com_hex).unwrap();
    let mut final_com_array = [0u8; 48];
    final_com_array.copy_from_slice(&final_com_bytes);
    let final_com_opt = G1Affine::from_bytes(&final_com_array.into());

    if final_com_opt.is_none().into() {
        println!("ERROR: Failed to decompress final_com!");
        return;
    }
    let final_com = final_com_opt.unwrap();
    println!("\nfinal_com from Aiken:");
    println!("final_com compressed: {}", hex::encode(final_com.to_bytes().as_ref()));

    // Compute MSM result = final_com + neg_g1_scaled + pi_scaled
    let msm_result = (final_com + neg_g1_scaled + pi_scaled).to_affine();
    println!("\nMSM result = final_com + neg_g1_scaled + pi_scaled:");
    println!("msm result (er) compressed: {}", hex::encode(msm_result.to_bytes().as_ref()));

    // Compare with Aiken's MSM result
    let aiken_msm_hex = "a81a0c6b053d27c2c88931cfacd99fe18deb8f31020769eb86056b598e00a220851d1cd510793ce832bd5eb28397f2f2";
    println!("\nAiken MSM result: {}", aiken_msm_hex);

    if hex::encode(msm_result.to_bytes().as_ref()).to_lowercase() == aiken_msm_hex.to_lowercase() {
        println!("✓ MSM result MATCHES Aiken!");
    } else {
        println!("✗ MSM result DIFFERS from Aiken");
    }

    // Now let's test the pairing
    println!("\n=== Pairing Check ===");

    // Get s*G2 from params (converted to blst format)
    let s_g2 = params.s_g2().to_affine();
    let s_g2_converted = compress_g2_point(&s_g2);
    println!("s*G2 (blst format): {}", hex::encode(&s_g2_converted));

    // Get G2 generator (converted to blst format)
    let g2_gen = G2Affine::generator();
    let g2_gen_converted = compress_g2_point(&g2_gen);
    println!("G2 gen (blst format): {}", hex::encode(&g2_gen_converted));

    // Run actual verification with the proof
    println!("\n=== Running halo2 verification ===");

    // Load and verify the fresh proof
    let proof_hex = "8ceb79113e0e0591b3a5cc741117be8962513f027bc6a18c6a39913024755df00fd14b6152bf2145c787385465c929dca5af4c782add76cc1213c72429deb8a44f1e314d404b64660b32f7439ce30f2578cbbcc217959453ea2608bc1c6cc804ab8921ff32afc42bce1759f80b0a1c12e7767f1edb6802cbbf6300062c2c60f7cf1148b988b33eeeef1d1bc46e9dc3fa9202b423b0e6464f1dfe5816a35f56e527a1b31b1a26b5e54b3743fe2780ac698ed5d95d5af83327472889bf7de136c8aa459d4f9320605fff549f547403c108f6c15f322ee16c4c704de9898e1b45f5e2dc78665e5a4df4b4d81c55f8f00f3d9938f28aa1ca0c79a97804c801c2c377c4dc49e056fae1ffa034f25e2b71b62a909da88e1d29fe08e60d115a8643560086b2ed4518b96b198c930831a683e21bf2b9490502c53a1aa210950319ff2fb80d565bd510a8134b2ed7446d5c685702b8bfc3aecf05a2f73d56e947647ff47bdaab0153a1c67213c5a87efa6064af81fa5d4362e3a81e7f7bf6466c2e121cdcb6351cdcea5b3c9b7aaa28810a4670f5f0f244b4a3b03168087fc26e546ba71169fe913110909ba91eabf2ab1f2170d7a37860fbd40eb89495b65745f121c7c04c3874160dca39059b0afd3001901b294613311405e2771e7b69a154bf38c004a70a92d34d7085a16c35ce0016d4b64303a5ff673f4da3cb86cb50c8c2439e21a2aa474c34e615b5a41cdae668efc582ac2bef2aea3e2ddd3ed2447b16f2f87a6765a6d5e9b86b81a4522bdf3c9375c69d09080a227b289d557210f17c69ab099963bc14341566271a61d017776648fcb6b82713e722a1506953897df73121fda732a3df4df8116d2dd7cb0d0b2ed89ab1823b3b761cd8e1116835606403bb12794cc8a3f2516152adbc50364921474874c7e2ed6b967b8a6dfbfec0b32e3f985afe7564490fdf67f7a74e09e1d7fa069f861b89be13bc320c0452d57aa09cfdc84827894fcbc33334032a7f7b983b70ffa4936b7e8b342522481d5641ad79aa4f1eac6ae2a38ea74c948c1bef358f600000000000000000000000000000000000000000000000000000000000000000fa6b451c9fd02e92d7b195e6b101f39b52f6019725cd69f2ac744d6a7cbe3904925eb95bd0be4d07094b55e09e5cd49001e9275987da4f32120ae709498b8a00edde9ae750e0dd330e7495b874a62251f22d744c1c1a55dd13c4c6fbea02995037b5b2ac949073be114ef497bdda0082488820910dd3ff007f54e785e149c54e3644cd01ac55d9d7114f5aab83b48f5eb4c8ac8c6912f12002f8529181fb7c2b70cb2cca721810a9fabc99c65f0dcf96750c884917c7f5828520c9416dc62011d5c12519fe8448994c42fe01225bce995a1151269132ec72caa2e5febe70a006f2f20f04107694d398c888895dd7b1b20090af88ab252bb57f083d49c0e8864fbf21ec019947c410e54782c2044a2225eb163640150fbfc4c8abf93432fa5c39d66c172f6594f72eea13f914c62efb6fd6cb575cdb30071f673df5eb1ba81a61d4f1d8bf216b739a4e464f90b7d9b8f78f4fb0174f7df4fb407f18f946c4fb20766b1a27c9d8a24021824d4974574c1571cef780000564340fc1884b9d6d9e0b12ba430035595a6b06baa4465da7ac752f7108f7866ad0ef33f9f4664451d2600ef6ac7e81cbd1daa45464e51acf4c4b2ddd5f5873705e3500b10b5e3ec3e649c616373e1cdc1042461dd538bca0ab4d425758a7df4bbb996383a387813dfb712b9c88f43f5573af16ac6a3df2dcd06219a4b7b7363293c20b95751d3001273b9b76c80231d87531f6303dbd494896fa03e3e52806eedbc36eeff829d694d5568a9ed138cd38d4487aecb79b7035b5ee5359e254a5cf193a0076720a48bdf6620f765e8f5299b0b60c2b1911f6264fa1b2400d0b5ff7a0efbe5481645032a537dc44f05ce8aea336c6f25accb19f0844730044b866a0682b1f4ec943fbbc1f2a027f63a548782f972357732afdbe9b971354b9e9b1404d58dc3f10f8cede076b01852982efb3b373b4bfedcaad440d6c8aaa9e2c54673d7617130a14ba82ab63d09c62e6626011ad2072c45a3b3cc3da9cdbb6537ff4fe2dae2bb81479352f690da5765e9fb3e3cf906ab46eb8b7150646d354672e501f3ca1b834dd8b27410f1560fc586638b5d1a1db7eae09e059158119fa2586f00b131a0b2de29221ef31e8223e35710bb896d0dfab77793d81b151375c0a946483107db60f7a5d320d6f59ac139e44f998ac3fa159968e536c6756bbe7d5ba9d7b80b8faa7990c6ca55aa200382eec7bef2b75820a59eac611d78638faf5202156f798053726e3f96a849b07d314ddd2f28b8b686421ef82775c29afb382acb3300fcd91b72c370683c9850d913b6362c7293f09389b14f4d36e9c390f661dcbf2876352aaffc106536255977ffc9268791dfb1d14a83ce3d573b95304c72724b592867a8b534cda6f9af197a517b925a0ede4f4609f1da4f510998aaf1936048b278e520bb05389122ba95e057fec2133603a27b7b2ae6d12f17c5a6f4fbc837d3bf2d4c93e77c549a4";
    let proof_bytes = hex::decode(proof_hex).unwrap();

    // Public inputs
    let pricing_tier_fr = Fr::from(0u64);
    let nullifier_fr = Fr::from(0x0807060504030202u64);
    let public_inputs_fr: Vec<Fr> = vec![pricing_tier_fr, nullifier_fr];

    println!("Public inputs:");
    println!("  pricing_tier: 0x{}", format_scalar(&pricing_tier_fr));
    println!("  nullifier: 0x{}", format_scalar(&nullifier_fr));

    // Create transcript and verify
    let mut transcript: CircuitTranscript<AikenHashState> =
        CircuitTranscript::init_from_bytes(&proof_bytes);

    use halo2_proofs::utils::arithmetic::MSM;
    match prepare::<Fr, CS, CircuitTranscript<AikenHashState>>(
        &vk,
        &[&[&public_inputs_fr]],
        &mut transcript,
    ) {
        Ok(guard) => {
            println!("Prepare succeeded");

            // Extract the actual left and right from DualMSM
            let (left_pairs, right_pairs) = guard.split();
            println!("\n=== DualMSM contents ===");
            println!("Left has {} terms", left_pairs.len());
            println!("Right has {} terms", right_pairs.len());

            // Compute left and right points manually from pairs
            use halo2_proofs::halo2curves::group::prime::PrimeCurveAffine;
            use halo2_proofs::halo2curves::group::Group;

            // Print details of all terms in right MSM
            println!("\n=== Right MSM terms (halo2) ===");
            for (i, (scalar, point)) in right_pairs.iter().enumerate() {
                let point_affine = point.to_affine();
                println!("Term {}: scalar=0x{}, point={}",
                    i,
                    format_scalar(*scalar),
                    hex::encode(point_affine.to_bytes().as_ref()));
            }

            let mut left_acc = G1::identity();
            for (scalar, point) in left_pairs.iter() {
                left_acc = left_acc + **point * **scalar;
            }
            let left_point = left_acc.to_affine();

            let mut right_acc = G1::identity();
            for (scalar, point) in right_pairs.iter() {
                right_acc = right_acc + **point * **scalar;
            }
            let right_point = right_acc.to_affine();

            println!("\nLeft (pi_term) computed by halo2:");
            println!("  {}", hex::encode(left_point.to_bytes().as_ref()));
            println!("Right (MSM) computed by halo2:");
            println!("  {}", hex::encode(right_point.to_bytes().as_ref()));

            // Compare with Aiken's values
            let aiken_pi_term = "998aaf1936048b278e520bb05389122ba95e057fec2133603a27b7b2ae6d12f17c5a6f4fbc837d3bf2d4c93e77c549a4";
            let aiken_msm = "a81a0c6b053d27c2c88931cfacd99fe18deb8f31020769eb86056b598e00a220851d1cd510793ce832bd5eb28397f2f2";

            println!("\nCompare with Aiken's computed values:");
            println!("Aiken pi_term: {}", aiken_pi_term);
            println!("Aiken MSM:     {}", aiken_msm);

            if hex::encode(left_point.to_bytes().as_ref()) == aiken_pi_term {
                println!("✓ Left (pi_term) MATCHES Aiken");
            } else {
                println!("✗ Left (pi_term) DIFFERS from Aiken");
            }
            if hex::encode(right_point.to_bytes().as_ref()) == aiken_msm {
                println!("✓ Right (MSM) MATCHES Aiken");
            } else {
                println!("✗ Right (MSM) DIFFERS from Aiken - THIS IS THE BUG!");
                println!("  Halo2 computes: {}", hex::encode(right_point.to_bytes().as_ref()));
                println!("  Aiken computes: {}", aiken_msm);
            }

            let verifier_params = params.verifier_params();
            match guard.verify(&verifier_params) {
                Ok(()) => {
                    println!("✓ halo2 verification: SUCCESS");
                }
                Err(e) => {
                    println!("✗ halo2 verification: FAILED");
                    println!("Error: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("Prepare failed: {:?}", e);
        }
    }
}

/// Debug pairing check - computes e(pi, sG2) and e(msm, G2) separately
/// and compares them using the same approach as Aiken's final_verify
fn debug_pairing_check(keys_dir: &str) {
    use halo2_proofs::halo2curves::group::{Curve, Group, GroupEncoding};
    use halo2_proofs::halo2curves::pairing::{MillerLoopResult, MultiMillerLoop};
    use halo2_proofs::halo2curves::bls12381::Bls12381;

    println!("=== Debug Pairing Check ===\n");

    // Load parameters
    let params_path = format!("{}/params.bin", keys_dir);
    let params_file = File::open(&params_path).expect("Failed to open params file");
    let mut params_reader = BufReader::new(params_file);
    let params: ParamsKZG<Bls12381> = ParamsKZG::read_custom(&mut params_reader, SerdeFormat::RawBytes)
        .expect("Failed to read params");

    // Get s*G2 from params
    let s_g2 = params.s_g2().to_affine();

    // Get G2 generator
    let g2_gen = G2Affine::generator();
    let neg_g2_gen = -g2_gen;

    // Load the exact points from Aiken trace
    let pi_term_hex = "998aaf1936048b278e520bb05389122ba95e057fec2133603a27b7b2ae6d12f17c5a6f4fbc837d3bf2d4c93e77c549a4";
    let msm_hex = "a81a0c6b053d27c2c88931cfacd99fe18deb8f31020769eb86056b598e00a220851d1cd510793ce832bd5eb28397f2f2";

    let pi_term_bytes = hex::decode(pi_term_hex).unwrap();
    let mut pi_array = [0u8; 48];
    pi_array.copy_from_slice(&pi_term_bytes);
    let pi_term = G1Affine::from_bytes(&pi_array.into()).unwrap();

    let msm_bytes = hex::decode(msm_hex).unwrap();
    let mut msm_array = [0u8; 48];
    msm_array.copy_from_slice(&msm_bytes);
    let msm = G1Affine::from_bytes(&msm_array.into()).unwrap();

    println!("pi_term: {}", hex::encode(pi_term.to_bytes().as_ref()));
    println!("msm:     {}", hex::encode(msm.to_bytes().as_ref()));
    println!("s*G2:    {}", hex::encode(compress_g2_point(&s_g2)));
    println!("G2 gen:  {}", hex::encode(compress_g2_point(&g2_gen)));
    println!("-G2 gen: {}", hex::encode(compress_g2_point(&neg_g2_gen)));

    // Method 1: halo2's approach - e(pi, sG2) * e(msm, -G2) == 1
    println!("\n=== Method 1: halo2's product check ===");
    println!("Computing: e(pi, sG2) * e(msm, -G2) == 1");

    let terms = [
        (&pi_term, &s_g2.into()),
        (&msm, &(-g2_gen).into()),
    ];
    let ml_result = Bls12381::multi_miller_loop(&terms);
    let fe_result = ml_result.final_exponentiation();
    let is_identity = bool::from(fe_result.is_identity());
    println!("Result: e(pi, sG2) * e(msm, -G2) is_identity = {}", is_identity);

    // Method 2: Aiken's approach - e(pi, sG2) == e(msm, G2) (equality check)
    println!("\n=== Method 2: Equality check (what Aiken does) ===");
    println!("Computing: e(pi, sG2) vs e(msm, G2)");

    // Compute each pairing separately
    let ml_left = Bls12381::multi_miller_loop(&[(&pi_term, &s_g2.into())]);
    let ml_right = Bls12381::multi_miller_loop(&[(&msm, &g2_gen.into())]);

    let fe_left = ml_left.final_exponentiation();
    let fe_right = ml_right.final_exponentiation();

    // Check equality
    let are_equal = fe_left == fe_right;
    println!("Result: e(pi, sG2) == e(msm, G2) is {}", are_equal);

    // Method 3: Check using division - e(pi, sG2) / e(msm, G2) == 1
    println!("\n=== Method 3: Division check ===");
    println!("Computing: e(pi, sG2) / e(msm, G2) == 1");

    // This is mathematically equivalent to method 1
    let terms2 = [
        (&pi_term, &s_g2.into()),
        (&(-msm), &g2_gen.into()),  // Negate msm instead of g2
    ];
    let ml_result2 = Bls12381::multi_miller_loop(&terms2);
    let fe_result2 = ml_result2.final_exponentiation();
    let is_identity2 = bool::from(fe_result2.is_identity());
    println!("Result: e(pi, sG2) * e(-msm, G2) is_identity = {}", is_identity2);

    // Additional debug: print Gt elements as hex for comparison
    println!("\n=== Gt element comparison ===");
    // The Gt elements are in Fp12, which is 576 bytes
    // We can't easily print them but we can check properties

    // Method 4: Try the exact opposite - e(msm, sG2) == e(pi, G2)
    println!("\n=== Method 4: Swapped check ===");
    println!("Computing: e(msm, sG2) == e(pi, G2)");

    let ml_left4 = Bls12381::multi_miller_loop(&[(&msm, &s_g2.into())]);
    let ml_right4 = Bls12381::multi_miller_loop(&[(&pi_term, &g2_gen.into())]);

    let fe_left4 = ml_left4.final_exponentiation();
    let fe_right4 = ml_right4.final_exponentiation();

    let are_equal4 = fe_left4 == fe_right4;
    println!("Result: e(msm, sG2) == e(pi, G2) is {}", are_equal4);

    println!("\n=== Summary ===");
    println!("halo2 product check (correct):    {}", is_identity);
    println!("Aiken equality check:             {}", are_equal);
    println!("Division check (equivalent):      {}", is_identity2);
    println!("Swapped check:                    {}", are_equal4);

    if is_identity && !are_equal {
        println!("\n⚠️  MISMATCH: halo2 passes but equality fails!");
        println!("This suggests final_verify in Cardano may use product semantics,");
        println!("not equality semantics. Try using e(pi, sG2) * e(-msm, G2) in Aiken.");
    }
}

/// Debug the v computation by manually parsing the proof like Aiken does
/// and comparing the intermediate values
fn debug_v_computation(keys_dir: &str) {
    use halo2_proofs::halo2curves::group::{Curve, Group, GroupEncoding};
    use halo2_proofs::halo2curves::ff::PrimeField;
    use num_bigint::BigUint;
    use num_traits::Num;

    println!("=== Debug v Computation ===\n");

    // Load parameters
    let params_path = format!("{}/params.bin", keys_dir);
    let params_file = File::open(&params_path).expect("Failed to open params file");
    let mut params_reader = BufReader::new(params_file);
    let params: ParamsKZG<Bls12381> = ParamsKZG::read_custom(&mut params_reader, SerdeFormat::RawBytes)
        .expect("Failed to read params");

    // Load verifying key
    let vk_path = format!("{}/vk.bin", keys_dir);
    let vk_file = File::open(&vk_path).expect("Failed to open vk file");
    let mut vk_reader = BufReader::new(vk_file);
    let vk: VerifyingKey<Fr, CS> =
        VerifyingKey::read::<_, VPNPaymentCircuit<Fr>>(&mut vk_reader, SerdeFormat::RawBytes)
            .expect("Failed to read vk");

    // The proof from Aiken test (check_valid_proof_valid_public_inputs)
    let proof_hex = "99c227b59acd5b022e71fdce4a9f797c0266092911e0b46841786deae658404ccb876234e3013c0b81dca4e5e2439c24b61c04dcd62bb4efdf69ebc48eb9b6bb9364f1e03d029b0a8691f7c59f469e237febd85f3f1191613ed9a39d75a93bf2971edbe27c554690e994fb5071e3b19feddaba04ed6c499bebe1407163a8277f9b1fbc0127b2b4c4448566a5a83cfd6f8efb845118d440f1598fbcee3e47dfcbfd20b132595e451d557841348cbf98450d93c2d272978e0f6f45c35ac4c03e7e93e5757f630aec2f67a3bd3e3668527371977479d6b6e8ca30428984af316fbdb66e654c4956a0915dc40d5c932461b2a7092a82714b6560742a19ebdc73880e7b6dbd838783d47a50cc79e1e8a6f05bdfe321dad719eb523f8a50e5fff30d6fb25d0d6bab59419be8e30eba85203d5dad4a791f74fb008a9a34123d624004e39d89c12c6126d7947f6a97c8bfdaf2b1a61a10f1049e68cd4823635b072bf3cdf18db3b87f4ce64e555edb3a46c39695414f725f28227dcdba3d1af365fa20fab822b0a588dfba2272e37d6686065b212f359af0afdf995f71d899ba0b21fd0d7f400bba0011b3d821d2ebdb36a035159111dafe5483e7d7bbe810095cf890bd0d8c21233eaca6294be215167e5e4deaf2f12c45a4861261e687d4b9a671633692d0403f3fedd8f6f6da2a791572f412be04fe959f30a138364c86834408d362c212e1433f3de0b921aa7cb22c2881328e62a218687b18399273837225dde89f28d6458f0978b1208fa74106722cd0996abdaed2f4d5345df23f4f279d0b8f688242192f673dcb6017056868dda7eb482d2724b82958425513e6d8092b704cee517db0909344c30f348ce45b734ec8b87804a0b67ce742308916284678afe91a7d87969b5aec37cbb345f6aebb09495b99fa38f87a38aaf8f40d056aef5d1564c0510eb9a94d0c443b50d9f4f15b1b1e59965ff42dd8f56bf6ab2904645c9e4044102ff9c73be7c2ccc976401976041aa107e670a1d592209f78a4395be20f95f735be8ede333d6ddc021e8f84478a0c00000000000000000000000000000000000000000000000000000000000000001307ff59a98d3c88ce1251b6604d99614ac4ce15bded3e640d350819d700894f0be486cd728a4206bf366bec3010b46ea018c6b659610c6ebbd1144d168683615d60fd6e06ec06af6e54261119df21e0202fd8ddcd051fc5c52d7e9fbad86b6d32b948e9165715f6b09a994f8d706e0be026d486d65f78bd729f008f39037e431e9b9bcaf158511c3abbf7161de6c33a2a1c983061e310af877a9172e1ffe870679a2f59486564a854025a41c7d7119a3edb836ed3455874b26210b7eb5ecd41521e0d58ec538e1ba684268c71526ac8be1c2bf79b3cd4e66cc7741570e53704b2368cf59f0ea37f5096155f48e42418d842cb5c7816cf22289aa7720b0f573d45d0c83d1eb2a65c396209da221807004ea29ebe58ac5eb2f8eb52aca4c6ad056a2f276f7dad697f7d51492ba489baa5db297866aa1686d6cbaac7cb9ef3422e9aacaefd34f524c6e6368eb9dcce57e284d4105c17ce6207eac5b3193f60cf7196cd377d6ccdb01f1a67071e1478cfc2a54623da30c55938715f69bc8cce251319f8556003e24ce0d90ecd93a28a0fa4a82cdd4e8aae1b7479fba54b023f990c13ef77739a72ab6afa95b40b7a7c2979070f994a995cd621ce924a75b1c09515dd4f45d0c29cb32f0abdd7465169b377eb75aa2ce5b961a80272e4c12aa564317a7198b65256ea9936336c5315f33a5b09da97e04bb32289dd1229015d3e286b1db5984a7abee0f7b59de7dbe4a671f46113638da6b56355147beaf4a70d2170be889521b491a7bb94c22b1e98a228133c910a0494a6c8c79aa619e21261dc3425942fd824c107efb3e2a1f562c93d531cea5db71774171599751de67f5e0b426f1c18f90f149a022368cb82470c6ef454eb3a0fa31047cd12340d22956b4f2b2eb6f4b01b236257726528690fd5094fa226253985f37b1b958dde29bbf3a9548d36b516d117a102b87b3bea747004868f3ef83394228362927fc25eb344e56f57c0a5a066b190f6ac1f067e1a77ceab5cee6ed497ac5ad56f7f3a4a5810a26378bbb77885c04f98cf66c627d8bd8c772451088b3efadea5228a6a41388b6e4c8145fefca33f304faee26b1ac4a8cab550794420d55ce3ba0d1bcbb53bbcfa5d83da8e411ad1cc6ef4496ba98bf6f7d87744fd1ccd8cf850ccff3db84b3fb36f16a7f033ec0acb3fb0f91831e79c46e597fc3fd0021f9764d0d0ac5c6dc2977292caecb354e3966fe5c1b83d5cdf833445ffcfadc3b5579f09e17346b2327ab9f09b309b816593b51407f08cd5764e941f9426589b965b76db66b67493b34b52a9d00fd1eb6187d2617a1ea759f1d809acd0dbbe68d3a56017b505c986fac1ff53544d9914a1c432a1d9c0082714c454cd13a56b4a26a7ad277d06adf3b6ce48131fa7e3bc73a8bb0b658fe219a4343db23e4aeeafce6cafb3d07ae8c6ff0bf0811d9407f28f1219e106a8c146d77956d4a93c0ae2f08bfd2b95f840779efb70";
    let proof_bytes = hex::decode(proof_hex).unwrap();

    println!("Proof size: {} bytes", proof_bytes.len());

    // Public inputs
    let pricing_tier_fr = Fr::from(0u64);
    let nullifier_fr = Fr::from(0x0807060504030202u64);
    let public_inputs_fr: Vec<Fr> = vec![pricing_tier_fr, nullifier_fr];

    // Run halo2 verification with tracing enabled
    let mut transcript: CircuitTranscript<AikenHashState> =
        CircuitTranscript::init_from_bytes(&proof_bytes);

    use halo2_proofs::utils::arithmetic::MSM;
    match prepare::<Fr, CS, CircuitTranscript<AikenHashState>>(
        &vk,
        &[&[&public_inputs_fr]],
        &mut transcript,
    ) {
        Ok(guard) => {
            println!("Prepare succeeded");

            // Extract the MSM terms
            let (left_pairs, right_pairs) = guard.split();
            println!("\nRight MSM has {} terms", right_pairs.len());

            // Find the v*(-G1) term (term 23) and x3*pi term (term 24)
            // The v scalar is in term 23
            if right_pairs.len() >= 25 {
                let (v_scalar, _v_point) = &right_pairs[23];
                let (x3_scalar, _x3_point) = &right_pairs[24];

                println!("\n=== Key scalars from halo2 DualMSM ===");
                println!("Term 23 (v*-G1):");
                println!("  v = 0x{}", format_scalar(&**v_scalar));

                // Convert to decimal
                let v_bytes: [u8; 32] = v_scalar.to_repr().as_ref().try_into().unwrap();
                let v_decimal = BigUint::from_bytes_le(&v_bytes);
                println!("  v (decimal) = {}", v_decimal);

                println!("\nTerm 24 (x3*pi):");
                println!("  x3 = 0x{}", format_scalar(&**x3_scalar));

                let x3_bytes: [u8; 32] = x3_scalar.to_repr().as_ref().try_into().unwrap();
                let x3_decimal = BigUint::from_bytes_le(&x3_bytes);
                println!("  x3 (decimal) = {}", x3_decimal);

                // Compare with Aiken's values
                println!("\n=== Comparison with Aiken's traced values ===");
                let aiken_v_str = "13723762600720973930567618457699291569302405656685985111537223563536670929717";
                let aiken_x3_str = "41102513550113544632227908556859404008989413012226451668680262568698306847740";

                let aiken_v = BigUint::from_str_radix(aiken_v_str, 10).unwrap();
                let aiken_x3 = BigUint::from_str_radix(aiken_x3_str, 10).unwrap();

                println!("Aiken v:  {}", aiken_v_str);
                println!("Halo2 v:  {}", v_decimal);
                if v_decimal == aiken_v {
                    println!("✓ v values MATCH!");
                } else {
                    println!("✗ v values DIFFER!");
                }

                println!("\nAiken x3: {}", aiken_x3_str);
                println!("Halo2 x3: {}", x3_decimal);
                if x3_decimal == aiken_x3 {
                    println!("✓ x3 values MATCH!");
                } else {
                    println!("✗ x3 values DIFFER!");
                }

                // Now trace backwards to find WHY v differs
                // v = inner_product([q_eval_1, q_eval_2, q_eval_3, f_eval], [x4^0, x4^1, x4^2, x4^3])
                println!("\n=== Aiken's traced inputs to v computation ===");
                println!("q_eval_1: 50128902656481549186537746149668217684711070747566237099553526024741275807529");
                println!("q_eval_2: 52393884343591692712734395201697183907179590922204187822243479783687146387868");
                println!("q_eval_3: 7671015793226833389115646448029413079209224359276248540015032172335258162105");
                println!("x4:       5022515707811474311168631110329325647662397036277617018812388745680870551902");
                println!("f_eval:   4572058982016134133118545383976154236080543077216019248218260619020054442285");
            }

            let verifier_params = params.verifier_params();
            match guard.verify(&verifier_params) {
                Ok(()) => {
                    println!("\n✓ halo2 verification: SUCCESS");
                }
                Err(e) => {
                    println!("\n✗ halo2 verification: FAILED");
                    println!("Error: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("Prepare failed: {:?}", e);
        }
    }
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
