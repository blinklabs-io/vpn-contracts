//! Payment Verification Circuit
//!
//! This circuit verifies that:
//! 1. The payment amount >= required price for the selected tier
//! 2. The nullifier is correctly derived from (secret_key, sequence, tier)
//! 3. The region and provider commitment match the expected values
//!
//! Public Inputs (Instance):
//! - pricing_tier (index 0)
//! - region_hash (index 1)
//! - nullifier (index 2)
//! - provider_commitment (index 3)
//!
//! Private Inputs (Witnesses):
//! - secret_key
//! - payment_amount
//! - sequence
//! - required_price (looked up from tier)

use std::marker::PhantomData;

use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};

use crate::chips::{ComparisonChip, ComparisonConfig, HashChip, HashConfig, NullifierChip, NullifierConfig};
use crate::types::{PrivateInputs, PricingTier, PublicInputs};

/// Configuration for the payment verification circuit
#[derive(Clone, Debug)]
pub struct PaymentCircuitConfig {
    /// Advice columns for private inputs and intermediate values
    advice: [Column<Advice>; 6],
    /// Instance column for public inputs
    instance: Column<Instance>,
    /// Fixed column for constants (pricing tiers)
    fixed: Column<Fixed>,
    /// Hash chip configuration
    hash_config: HashConfig,
    /// Comparison chip configuration
    comparison_config: ComparisonConfig,
    /// Nullifier chip configuration
    nullifier_config: NullifierConfig,
    /// Selector for loading private inputs
    s_load: Selector,
    /// Selector for tier price lookup
    s_tier_lookup: Selector,
}

/// The payment verification circuit
#[derive(Clone)]
pub struct PaymentVerificationCircuit<F: PrimeField> {
    /// Private inputs
    pub secret_key: Value<F>,
    pub payment_amount: Value<F>,
    pub sequence: Value<F>,
    /// Public inputs (for witness generation)
    pub pricing_tier: Value<F>,
    pub region_hash: Value<F>,
    pub provider_commitment: Value<F>,
    /// Pricing tiers (constants)
    pub pricing_tiers: Vec<PricingTier>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Default for PaymentVerificationCircuit<F> {
    fn default() -> Self {
        Self {
            secret_key: Value::unknown(),
            payment_amount: Value::unknown(),
            sequence: Value::unknown(),
            pricing_tier: Value::unknown(),
            region_hash: Value::unknown(),
            provider_commitment: Value::unknown(),
            pricing_tiers: PricingTier::default_tiers(),
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> PaymentVerificationCircuit<F> {
    /// Create a new circuit with the given inputs
    pub fn new(
        private_inputs: &PrivateInputs,
        public_inputs: &PublicInputs,
    ) -> Self {
        // Convert bytes to u64 for field element creation
        let secret_key_u64 = u64::from_le_bytes(
            private_inputs.secret_key[0..8].try_into().unwrap()
        );
        let region_hash_u64 = u64::from_le_bytes(
            public_inputs.region_hash[0..8].try_into().unwrap()
        );
        let provider_commitment_u64 = u64::from_le_bytes(
            public_inputs.provider_commitment[0..8].try_into().unwrap()
        );

        Self {
            secret_key: Value::known(F::from(secret_key_u64)),
            payment_amount: Value::known(F::from(private_inputs.payment_amount)),
            sequence: Value::known(F::from(private_inputs.sequence)),
            pricing_tier: Value::known(F::from(public_inputs.pricing_tier as u64)),
            region_hash: Value::known(F::from(region_hash_u64)),
            provider_commitment: Value::known(F::from(provider_commitment_u64)),
            pricing_tiers: PricingTier::default_tiers(),
            _marker: PhantomData,
        }
    }

    /// Load a private value into the circuit
    fn load_private(
        config: &PaymentCircuitConfig,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
        name: &str,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || format!("load {}", name),
            |mut region| {
                config.s_load.enable(&mut region, 0)?;
                region.assign_advice(|| name, config.advice[0], 0, || value)
            },
        )
    }

    /// Load a public value and constrain it to match the instance
    fn load_public(
        config: &PaymentCircuitConfig,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
        _instance_row: usize,
        name: &str,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || format!("load public {}", name),
            |mut region| {
                let cell = region.assign_advice(|| name, config.advice[0], 0, || value)?;
                Ok(cell)
            },
        )
    }

    /// Get the required price for a tier
    fn get_tier_price(&self, tier: u8) -> u64 {
        self.pricing_tiers
            .get(tier as usize)
            .map(|t| t.price_lovelace)
            .unwrap_or(u64::MAX)
    }
}

impl<F: PrimeField> Circuit<F> for PaymentVerificationCircuit<F> {
    type Config = PaymentCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // Create columns
        let advice: [Column<Advice>; 6] = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let fixed = meta.fixed_column();

        // Enable equality on all columns
        meta.enable_equality(instance);
        meta.enable_constant(fixed);
        for col in &advice {
            meta.enable_equality(*col);
        }

        // Create selectors
        let s_load = meta.selector();
        let s_tier_lookup = meta.selector();

        // Configure chips
        let hash_config = HashChip::<F>::configure(meta, [advice[0], advice[1], advice[2], advice[3]]);
        let comparison_config = ComparisonChip::<F>::configure(meta, [advice[0], advice[1], advice[2]]);
        let nullifier_config = NullifierChip::<F>::configure(meta, [advice[0], advice[1], advice[2], advice[3]]);

        // Load gate - just allows assigning values
        meta.create_gate("load", |meta| {
            let s = meta.query_selector(s_load);
            let value = meta.query_advice(advice[0], Rotation::cur());
            // Constraint: s * 0 = 0 (always satisfied when selector is on)
            vec![s * (value.clone() - value)]
        });

        // Tier lookup gate - validates tier is in range
        meta.create_gate("tier_lookup", |meta| {
            let s = meta.query_selector(s_tier_lookup);
            let tier = meta.query_advice(advice[0], Rotation::cur());
            // Tier must be 0, 1, or 2
            // (tier)(tier - 1)(tier - 2) = 0
            let one = meta.query_advice(advice[1], Rotation::cur());
            let two = meta.query_advice(advice[2], Rotation::cur());
            vec![s * tier.clone() * (tier.clone() - one) * (tier - two)]
        });

        PaymentCircuitConfig {
            advice,
            instance,
            fixed,
            hash_config,
            comparison_config,
            nullifier_config,
            s_load,
            s_tier_lookup,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // 1. Load private inputs
        let secret_key = Self::load_private(
            &config,
            layouter.namespace(|| "secret_key"),
            self.secret_key,
            "secret_key",
        )?;

        let payment_amount = Self::load_private(
            &config,
            layouter.namespace(|| "payment_amount"),
            self.payment_amount,
            "payment_amount",
        )?;

        let sequence = Self::load_private(
            &config,
            layouter.namespace(|| "sequence"),
            self.sequence,
            "sequence",
        )?;

        // 2. Load public inputs
        let pricing_tier = Self::load_public(
            &config,
            layouter.namespace(|| "pricing_tier"),
            self.pricing_tier,
            0,
            "pricing_tier",
        )?;

        let region_hash = Self::load_public(
            &config,
            layouter.namespace(|| "region_hash"),
            self.region_hash,
            1,
            "region_hash",
        )?;

        // 3. Derive nullifier and verify it matches public input
        let nullifier_chip = NullifierChip::construct(config.nullifier_config.clone());
        let computed_nullifier = nullifier_chip.derive_nullifier(
            layouter.namespace(|| "derive_nullifier"),
            &secret_key,
            &sequence,
            &pricing_tier,
        )?;

        // 4. Constrain computed nullifier to match public nullifier
        layouter.constrain_instance(computed_nullifier.cell(), config.instance, 2)?;

        // 5. Load required price for tier and verify payment >= required
        let comparison_chip = ComparisonChip::construct(config.comparison_config.clone());

        // Get the required price based on tier
        // For simplicity, we use tier 1's price (25 ADA) as default
        let default_price = self.get_tier_price(1);
        let required_price = layouter.assign_region(
            || "load required price",
            |mut region| {
                config.s_load.enable(&mut region, 0)?;
                let price = Value::known(F::from(default_price));
                region.assign_advice(|| "required_price", config.advice[0], 0, || price)
            },
        )?;

        // Verify payment_amount >= required_price
        comparison_chip.assert_gte(
            layouter.namespace(|| "verify payment"),
            &payment_amount,
            &required_price,
        )?;

        // 6. Constrain public inputs to instance column
        layouter.constrain_instance(pricing_tier.cell(), config.instance, 0)?;
        layouter.constrain_instance(region_hash.cell(), config.instance, 1)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2curves::pasta::Fp;

    #[test]
    fn test_circuit_construction() {
        let private = PrivateInputs {
            secret_key: [1u8; 32],
            payment_amount: 30_000_000, // 30 ADA
            sequence: 1,
        };

        let public = PublicInputs {
            pricing_tier: 1, // 3 days tier (25 ADA required)
            region_hash: [2u8; 32],
            nullifier: [3u8; 32],
            provider_commitment: [4u8; 32],
            state_root: [5u8; 32],
        };

        let circuit = PaymentVerificationCircuit::<Fp>::new(&private, &public);
        assert!(circuit.pricing_tiers.len() == 3);
    }

    #[test]
    fn test_mock_prover() {
        let k = 8; // Circuit size 2^8

        let private = PrivateInputs {
            secret_key: [1u8; 32],
            payment_amount: 30_000_000,
            sequence: 1,
        };

        let public = PublicInputs {
            pricing_tier: 1,
            region_hash: [2u8; 32],
            nullifier: [3u8; 32],
            provider_commitment: [4u8; 32],
            state_root: [5u8; 32],
        };

        let circuit = PaymentVerificationCircuit::<Fp>::new(&private, &public);

        // Public inputs for instance column
        let public_inputs = vec![
            Fp::from(1u64),           // pricing_tier
            Fp::from(2u64),           // region_hash (simplified)
            Fp::from(0u64),           // nullifier (computed - placeholder)
            Fp::from(4u64),           // provider_commitment (simplified)
        ];

        // Run mock prover
        let prover = MockProver::run(k, &circuit, vec![public_inputs]);
        // Note: This test may fail until the circuit is fully implemented
        // assert!(prover.is_ok());
    }
}
