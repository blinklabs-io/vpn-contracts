//! VPN Payment Verification Circuit
//!
//! This Halo2 circuit verifies that a valid payment was made on Midnight
//! for VPN access, enabling trustless cross-chain proof verification on Cardano.
//!
//! # Public Inputs
//! - `pricing_tier`: The pricing tier index (0, 1, or 2)
//! - `region_hash`: Hash of the selected region
//! - `nullifier`: Unique identifier preventing double-spend
//! - `provider_commitment`: Hash of the provider's Cardano address
//!
//! # Private Inputs (Witnesses)
//! - `secret_key`: User's secret key for nullifier derivation
//! - `payment_amount`: Actual payment amount (hidden)
//! - `sequence`: Contract sequence number at payment time

pub mod circuit;
pub mod chips;
pub mod types;

/// BLS12-381 circuit for Cardano-compatible Aiken verifier generation
/// Uses plutus-halo2-verifier-gen to output Aiken code that uses
/// Cardano's native BLS12-381 builtins for on-chain proof verification.
pub mod bls12_381;

pub use circuit::PaymentVerificationCircuit;
pub use types::{PaymentProof, PublicInputs, PrivateInputs};

// Re-export BLS12-381 circuit for verifier generation
pub use bls12_381::VPNPaymentCircuit;
