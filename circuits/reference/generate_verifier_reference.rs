// =============================================================================
// REFERENCE CODE - NOT COMPILABLE IN THIS REPOSITORY
// =============================================================================
//
// This file documents how the Aiken verifier code was originally generated
// using IOG's plutus-halo2-verifier-gen tool. It is preserved as a reference
// for future circuit modifications.
//
// WHY THIS DOESN'T COMPILE:
// -------------------------
// This code was designed to run within the plutus-halo2-verifier-gen repository,
// which uses IOG's fork of halo2. Our circuits/ crate uses Midnight's fork of
// halo2 as the primary dependency for proof generation. These two forks have
// incompatible APIs:
//
//   - IOG's halo2: Has `k_from_circuit`, `prepare`, `CircuitTranscript`,
//                  `PolynomialCommitmentScheme`, `gwc_kzg` module, etc.
//   - Midnight's halo2: Different API structure for the same operations
//
// The `plutus-halo2-verifier-gen` crate is included as a dependency to access
// its Aiken code generation functions, but its halo2 types conflict with
// Midnight's when used directly.
//
// HOW TO REGENERATE THE AIKEN VERIFIER:
// -------------------------------------
// If you need to modify the circuit and regenerate the Aiken verifier:
//
// 1. Clone plutus-halo2-verifier-gen separately:
//    git clone https://github.com/input-output-hk/plutus-halo2-verifier-gen
//
// 2. Copy circuits/src/bls12_381/mod.rs to their src/circuits/ directory
//
// 3. Add the module to their src/circuits/mod.rs
//
// 4. Adapt this reference code as an example in their examples/ directory
//
// 5. Run: cargo run --example <your_example_name>
//
// 6. Copy the generated Aiken files from aiken-verifier/aiken_halo2/lib/
//    to midnight/contract/lib/halo2/
//
// GENERATED FILES:
// ----------------
// The following Aiken verifier files were generated and are located in
// midnight/contract/lib/halo2/:
//   - proof_verifier.ak  - Main verification logic
//   - verifier_key.ak    - Verification key constants
//   - bls_utils.ak       - BLS12-381 utility functions
//   - halo2_kzg.ak       - KZG commitment scheme implementation
//   - lagrange.ak        - Lagrange interpolation
//   - omega_rotations.ak - Rotation constants
//   - transcript.ak      - Fiat-Shamir transcript
//
// =============================================================================

//! VPN Payment Verification Circuit - Aiken Verifier Generator
//!
//! Generates an Aiken verifier for VPN payment proofs that can be
//! deployed as a reference script on Cardano.

use anyhow::{Context as _, Result, anyhow, bail};
use blstrs::{Bls12, G1Projective, Scalar};
use halo2_proofs::{
    plonk::{
        ProvingKey, VerifyingKey, create_proof, k_from_circuit, keygen_pk, keygen_vk, prepare,
    },
    poly::{
        commitment::{Guard, PolynomialCommitmentScheme}, gwc_kzg::GwcKZGCommitmentScheme,
        kzg::KZGCommitmentScheme, kzg::params::ParamsKZG, kzg::params::ParamsVerifierKZG,
    },
    transcript::{CircuitTranscript, Transcript},
};
use log::{debug, info};
use plutus_halo2_verifier_gen::plutus_gen::generate_aiken_verifier;
use plutus_halo2_verifier_gen::plutus_gen::proof_serialization::export_proof;
use plutus_halo2_verifier_gen::plutus_gen::{
    adjusted_types::CardanoFriendlyState, extraction::ExtractKZG, generate_plinth_verifier,
    proof_serialization::export_public_inputs, proof_serialization::serialize_proof,
};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use std::env;
use std::fs::File;

// Import VPN circuit from our local crate
use vpn_payment_circuit::bls12_381::VPNPaymentCircuit;

fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", "info"));

    let args: Vec<String> = env::args().collect();

    match &args[1..] {
        [] => compile_vpn_payment_circuit::<KZGCommitmentScheme<Bls12>>(),
        [command] if command == "gwc_kzg" => {
            compile_vpn_payment_circuit::<GwcKZGCommitmentScheme<Bls12>>()
        }
        _ => {
            println!("Usage:");
            println!("- to run the example: `cargo run --example vpn_payment`");
            println!(
                "- to run with GWC19 KZG: `cargo run --example vpn_payment gwc_kzg`"
            );

            bail!("Invalid command line arguments")
        }
    }
}

fn compile_vpn_payment_circuit<
    S: PolynomialCommitmentScheme<
            Scalar,
            Commitment = G1Projective,
            Parameters = ParamsKZG<Bls12>,
            VerifierParameters = ParamsVerifierKZG<Bls12>,
        > + ExtractKZG,
>() -> Result<()> {
    info!("Generating VPN Payment Verification Circuit...");

    // Test inputs
    let secret_key = Scalar::from(12345u64);
    let payment_amount = Scalar::from(30_000_000u64); // 30 ADA
    let sequence = Scalar::from(1u64);
    let pricing_tier = Scalar::from(1u64); // Tier 1
    let region_hash = Scalar::from(999u64);
    let required_price = Scalar::from(25_000_000u64); // 25 ADA required for tier 1

    info!("secret_key: {:?}", secret_key);
    info!("payment_amount: {:?}", payment_amount);
    info!("sequence: {:?}", sequence);
    info!("pricing_tier: {:?}", pricing_tier);
    info!("region_hash: {:?}", region_hash);
    info!("required_price: {:?}", required_price);

    // Create circuit
    let circuit = VPNPaymentCircuit::new(
        secret_key,
        payment_amount,
        sequence,
        pricing_tier,
        region_hash,
        required_price,
    );
    debug!("circuit: {:?}", circuit);

    let seed = [0u8; 32]; // UNSAFE, constant seed for testing
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    let k: u32 = k_from_circuit(&circuit);
    info!("Circuit k value: {}", k);

    let params: ParamsKZG<Bls12> = ParamsKZG::<Bls12>::unsafe_setup(k, rng.clone());
    let vk: VerifyingKey<_, S> =
        keygen_vk(&params, &circuit).context("keygen_vk should not fail")?;
    let pk: ProvingKey<_, S> =
        keygen_pk(vk.clone(), &circuit).context("keygen_pk should not fail")?;

    let mut transcript: CircuitTranscript<CardanoFriendlyState> =
        CircuitTranscript::<CardanoFriendlyState>::init();
    debug!("transcript: {:?}", transcript);

    // Public inputs: pricing_tier and nullifier
    // nullifier = secret_key + sequence + pricing_tier (simplified hash)
    let expected_nullifier = secret_key + sequence + pricing_tier;
    let instances: &[&[&[Scalar]]] = &[&[&[pricing_tier, expected_nullifier]]];
    info!("Public inputs: {:?}", instances);

    // Export public inputs for Plinth
    let instances_file =
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).context("failed to create instances file")?;
    export_public_inputs(instances, &mut output).context("failed to export public inputs")?;

    // Create proof
    info!("Creating proof...");
    create_proof(
        &params,
        &pk,
        &[circuit],
        instances,
        &mut rng,
        &mut transcript,
    )
    .context("proof generation should not fail")?;

    let proof = transcript.finalize();
    info!("Proof size: {} bytes", proof.len());

    // Create invalid proof for testing
    let mut invalid_proof = proof.clone();
    let index = 48 * 4 + 2; // Flip a byte in the proof
    invalid_proof[index] = !invalid_proof[index];

    // Verify the proof
    info!("Verifying proof...");
    let mut transcript_verifier: CircuitTranscript<CardanoFriendlyState> =
        CircuitTranscript::<CardanoFriendlyState>::init_from_bytes(&proof);
    let verifier = prepare::<_, _, CircuitTranscript<CardanoFriendlyState>>(
        &vk,
        instances,
        &mut transcript_verifier,
    )
    .context("prepare verification failed")?;

    verifier
        .verify(&params.verifier_params())
        .map_err(|e| anyhow!("{e:?}"))
        .context("verify failed")?;

    info!("Proof verified successfully!");

    // Serialize proof for Plinth
    serialize_proof(
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.json".to_string(),
        proof.clone(),
    )
    .context("json proof serialization failed")?;

    export_proof(
        "./plinth-verifier/plutus-halo2/test/Generic/serialized_proof.hex".to_string(),
        proof.clone(),
    )
    .context("hex proof serialization failed")?;

    // Generate Plinth verifier
    info!("Generating Plinth verifier...");
    generate_plinth_verifier(&params, &vk, instances)
        .context("Plinth verifier generation failed")?;

    // Generate Aiken verifier
    info!("Generating Aiken verifier...");
    generate_aiken_verifier(
        &params,
        &vk,
        instances,
        Some((proof.clone(), invalid_proof)),
    )
    .context("Aiken verifier generation failed")?;

    // Export proof for Aiken
    export_proof(
        "./aiken-verifier/submitter/serialized_proof.hex".to_string(),
        proof,
    )
    .context("hex proof serialization failed")?;

    let instances_file = "./aiken-verifier/submitter/serialized_public_input.hex".to_string();
    let mut output = File::create(instances_file).context("failed to create instances file")?;
    export_public_inputs(instances, &mut output).context("Failed to export public inputs")?;

    info!("VPN Payment verifier generation complete!");
    info!("Aiken verifier written to: ./aiken-verifier/aiken_halo2/lib/proof_verifier.ak");
    info!("Aiken VK written to: ./aiken-verifier/aiken_halo2/lib/vk.ak");

    Ok(())
}
