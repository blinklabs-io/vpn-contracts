//! VPN Payment Verification Circuit
//!
//! This circuit verifies that:
//! 1. The payment amount >= required price for the selected tier
//! 2. The nullifier is correctly derived from (secret_key, sequence, tier)
//!
//! Public Inputs (Instance):
//! - pricing_tier
//! - nullifier_hash (first 32 bytes)

use ff::Field;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

/// Pricing tier prices in lovelace
pub const TIER_PRICES: [u64; 3] = [
    10_000_000,  // Tier 0: 10 ADA (1 day)
    25_000_000,  // Tier 1: 25 ADA (3 days)
    50_000_000,  // Tier 2: 50 ADA (7 days)
];

// ============================================================================
// Configuration for the VPN payment circuit
// ============================================================================

#[derive(Clone, Debug)]
pub struct VPNPaymentConfig {
    /// Advice columns for private inputs and intermediate values
    advice: [Column<Advice>; 4],
    /// Instance column for public inputs
    instance: Column<Instance>,
    /// Fixed column for constants
    fixed: Column<Fixed>,
    /// Selector for loading values
    s_load: Selector,
    /// Selector for hash computation (simplified)
    s_hash: Selector,
    /// Selector for comparison (a >= b)
    s_gte: Selector,
}

// ============================================================================
// Field Chip - Basic field operations
// ============================================================================

struct FieldChip<F: Field> {
    config: VPNPaymentConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for FieldChip<F> {
    type Config = VPNPaymentConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> FieldChip<F> {
    fn construct(config: VPNPaymentConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = &self.config;
        layouter.assign_region(
            || "load private",
            |mut region| {
                config.s_load.enable(&mut region, 0)?;
                region.assign_advice(|| "private input", config.advice[0], 0, || value)
            },
        )
    }

    fn load_constant(
        &self,
        mut layouter: impl Layouter<F>,
        constant: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = &self.config;
        layouter.assign_region(
            || "load constant",
            |mut region| {
                region.assign_advice_from_constant(
                    || "constant value",
                    config.advice[0],
                    0,
                    constant,
                )
            },
        )
    }

    /// Compute hash of inputs (simplified - just sum for demo)
    /// In production, this would implement proper Blake2b constraints
    fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
        c: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = &self.config;
        layouter.assign_region(
            || "hash",
            |mut region: Region<'_, F>| {
                config.s_hash.enable(&mut region, 0)?;

                a.copy_advice(|| "input_a", &mut region, config.advice[0], 0)?;
                b.copy_advice(|| "input_b", &mut region, config.advice[1], 0)?;
                c.copy_advice(|| "input_c", &mut region, config.advice[2], 0)?;

                // Simplified hash: a + b + c (placeholder for actual Blake2b)
                let hash_value = a.value().copied() + b.value().copied() + c.value().copied();
                region.assign_advice(|| "hash output", config.advice[3], 0, || hash_value)
            },
        )
    }

    /// Assert that a >= b
    fn assert_gte(
        &self,
        mut layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<(), Error> {
        let config = &self.config;
        layouter.assign_region(
            || "gte check",
            |mut region: Region<'_, F>| {
                config.s_gte.enable(&mut region, 0)?;

                a.copy_advice(|| "a", &mut region, config.advice[0], 0)?;
                b.copy_advice(|| "b", &mut region, config.advice[1], 0)?;

                // diff = a - b (must be non-negative)
                let diff = a.value().copied() - b.value().copied();
                region.assign_advice(|| "diff", config.advice[2], 0, || diff)?;

                Ok(())
            },
        )
    }
}

// ============================================================================
// VPN Payment Verification Circuit
// ============================================================================

#[derive(Clone, Debug)]
pub struct VPNPaymentCircuit<F: Field> {
    /// Private: User's secret key (for nullifier derivation)
    pub secret_key: Value<F>,
    /// Private: Payment amount in lovelace
    pub payment_amount: Value<F>,
    /// Private: Sequence number for this payment
    pub sequence: Value<F>,
    /// Public: Pricing tier (0, 1, or 2)
    pub pricing_tier: Value<F>,
    /// Public: Region hash
    pub region_hash: Value<F>,
    /// Constant: Required price for this tier
    pub required_price: F,
    _marker: PhantomData<F>,
}

impl<F: Field> Default for VPNPaymentCircuit<F> {
    fn default() -> Self {
        Self {
            secret_key: Value::unknown(),
            payment_amount: Value::unknown(),
            sequence: Value::unknown(),
            pricing_tier: Value::unknown(),
            region_hash: Value::unknown(),
            required_price: F::ZERO,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> VPNPaymentCircuit<F> {
    pub fn new(
        secret_key: F,
        payment_amount: F,
        sequence: F,
        pricing_tier: F,
        region_hash: F,
        required_price: F,
    ) -> Self {
        Self {
            secret_key: Value::known(secret_key),
            payment_amount: Value::known(payment_amount),
            sequence: Value::known(sequence),
            pricing_tier: Value::known(pricing_tier),
            region_hash: Value::known(region_hash),
            required_price,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> Circuit<F> for VPNPaymentCircuit<F> {
    type Config = VPNPaymentConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // Create columns
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let fixed = meta.fixed_column();

        // Enable equality constraints
        meta.enable_equality(instance);
        meta.enable_constant(fixed);
        for col in &advice {
            meta.enable_equality(*col);
        }

        // Create selectors
        let s_load = meta.selector();
        let s_hash = meta.selector();
        let s_gte = meta.selector();

        // Load gate - allows assigning values
        meta.create_gate("load", |meta| {
            let s = meta.query_selector(s_load);
            let value = meta.query_advice(advice[0], Rotation::cur());
            vec![s * (value.clone() - value)]
        });

        // Hash gate (simplified)
        meta.create_gate("hash", |meta| {
            let s = meta.query_selector(s_hash);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            let out = meta.query_advice(advice[3], Rotation::cur());
            // Constraint: out = a + b + c (simplified hash)
            vec![s * (a + b + c - out)]
        });

        // Greater-than-or-equal gate
        // Constraint: a - b = diff (diff must be non-negative)
        meta.create_gate("gte", |meta| {
            let s = meta.query_selector(s_gte);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let diff = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a - b - diff)]
        });

        VPNPaymentConfig {
            advice,
            instance,
            fixed,
            s_load,
            s_hash,
            s_gte,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let field_chip = FieldChip::construct(config.clone());

        // 1. Load private inputs
        let secret_key = field_chip.load_private(
            layouter.namespace(|| "secret_key"),
            self.secret_key,
        )?;

        let payment_amount = field_chip.load_private(
            layouter.namespace(|| "payment_amount"),
            self.payment_amount,
        )?;

        let sequence = field_chip.load_private(
            layouter.namespace(|| "sequence"),
            self.sequence,
        )?;

        // 2. Load public inputs
        let pricing_tier = field_chip.load_private(
            layouter.namespace(|| "pricing_tier"),
            self.pricing_tier,
        )?;

        let _region_hash = field_chip.load_private(
            layouter.namespace(|| "region_hash"),
            self.region_hash,
        )?;

        // 3. Derive nullifier: hash(secret_key, sequence, pricing_tier)
        let nullifier = field_chip.hash(
            layouter.namespace(|| "derive_nullifier"),
            &secret_key,
            &sequence,
            &pricing_tier,
        )?;

        // 4. Load required price for the selected tier
        let required_price = field_chip.load_constant(
            layouter.namespace(|| "required_price"),
            self.required_price,
        )?;

        // 5. Verify payment_amount >= required_price
        field_chip.assert_gte(
            layouter.namespace(|| "verify_payment"),
            &payment_amount,
            &required_price,
        )?;

        // 6. Constrain public inputs to instance column
        layouter.constrain_instance(pricing_tier.cell(), config.instance, 0)?;
        layouter.constrain_instance(nullifier.cell(), config.instance, 1)?;

        Ok(())
    }
}

// Note: Tests for this BLS12-381 circuit require IOG's halo2 fork
// (used by plutus-halo2-verifier-gen), not Midnight's halo2 fork.
// The circuit is tested when running the generate_verifier example.
//
// Known limitation: The simplified GTE constraint (a - b = diff) doesn't
// enforce that diff is non-negative in a finite field. A production circuit
// would need proper range checks using bit decomposition or lookup tables.
