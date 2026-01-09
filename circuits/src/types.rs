//! Type definitions for the VPN payment verification circuit

use serde::{Deserialize, Serialize};

/// Public inputs to the circuit (visible on Cardano)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Pricing tier index (0 = 1 hour, 1 = 3 days, 2 = 1 year)
    pub pricing_tier: u8,
    /// Hash of the selected region (32 bytes)
    pub region_hash: [u8; 32],
    /// Unique nullifier to prevent double-spend (32 bytes)
    pub nullifier: [u8; 32],
    /// Hash of provider's Cardano address (32 bytes)
    pub provider_commitment: [u8; 32],
    /// Midnight state root at payment time (32 bytes)
    pub state_root: [u8; 32],
}

/// Private inputs to the circuit (kept secret)
#[derive(Clone, Debug)]
pub struct PrivateInputs {
    /// User's secret key for nullifier derivation (32 bytes)
    pub secret_key: [u8; 32],
    /// Actual payment amount in lovelace
    pub payment_amount: u64,
    /// Contract sequence number at payment time
    pub sequence: u64,
}

/// Pricing tier configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PricingTier {
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Price in lovelace
    pub price_lovelace: u64,
}

impl PricingTier {
    /// Default pricing tiers matching Cardano contract
    pub fn default_tiers() -> Vec<Self> {
        vec![
            // Tier 0: 1 hour
            PricingTier {
                duration_ms: 3_600_000,
                price_lovelace: 5_000_000, // 5 ADA
            },
            // Tier 1: 3 days
            PricingTier {
                duration_ms: 259_200_000,
                price_lovelace: 25_000_000, // 25 ADA
            },
            // Tier 2: 1 year
            PricingTier {
                duration_ms: 31_536_000_000,
                price_lovelace: 100_000_000, // 100 ADA
            },
        ]
    }
}

/// Complete payment proof for Cardano submission
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentProof {
    /// The ZK proof bytes (Halo2 proof)
    pub proof: Vec<u8>,
    /// Public inputs
    pub public_inputs: PublicInputs,
}

impl PaymentProof {
    /// Serialize to JSON for Cardano script submission
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize to the format expected by the bash scripts
    pub fn to_script_format(&self) -> ScriptProofFormat {
        ScriptProofFormat {
            zk_proof: hex::encode(&self.proof),
            nullifier: hex::encode(self.public_inputs.nullifier),
            state_root: hex::encode(self.public_inputs.state_root),
            selection: self.public_inputs.pricing_tier as u32,
            region: hex::encode(self.public_inputs.region_hash),
        }
    }
}

/// Proof format for bash script consumption
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScriptProofFormat {
    pub zk_proof: String,
    pub nullifier: String,
    pub state_root: String,
    pub selection: u32,
    pub region: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pricing_tiers() {
        let tiers = PricingTier::default_tiers();
        assert_eq!(tiers.len(), 3);
        assert_eq!(tiers[0].duration_ms, 3_600_000);
        assert_eq!(tiers[1].duration_ms, 259_200_000);
        assert_eq!(tiers[2].duration_ms, 31_536_000_000);
    }

    #[test]
    fn test_script_format_serialization() {
        let proof = PaymentProof {
            proof: vec![1, 2, 3, 4],
            public_inputs: PublicInputs {
                pricing_tier: 1,
                region_hash: [0u8; 32],
                nullifier: [1u8; 32],
                provider_commitment: [2u8; 32],
                state_root: [3u8; 32],
            },
        };

        let script_format = proof.to_script_format();
        assert_eq!(script_format.selection, 1);
        assert_eq!(script_format.zk_proof, "01020304");
    }
}
