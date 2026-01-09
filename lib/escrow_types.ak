use aiken/crypto.{VerificationKeyHash}
use cardano/assets.{PolicyId}
use cardano/transaction.{OutputReference}

/// Configuration for Midnight ZK verification (stored in escrow config UTxO)
pub type EscrowConfig {
  /// Hash of Halo2 verifier (currently unused - verifier is embedded)
  verifier_hash: ByteArray,
  /// Whether Midnight payments are enabled
  midnight_enabled: Bool,
  /// ADA price per pricing tier (in lovelace)
  /// Must match VPN reference data pricing
  tier_prices: List<Int>,
  /// Provider address to receive payments
  provider_pkh: VerificationKeyHash,
  /// VPN policy ID for validation
  vpn_policy_id: PolicyId,
}

/// Datum for escrow UTxO (holds ADA pool)
pub type EscrowDatum {
  /// Total ADA available for Midnight payments
  total_ada: Int,
  /// Number of successful payments processed
  payment_count: Int,
}

/// Escrow spending redeemer - release funds for VPN minting
pub type EscrowSpendAction {
  /// Release funds after verifying ZK proof
  ReleaseFunds {
    /// ZK proof from Midnight
    zk_proof: ByteArray,
    /// Nullifier to prevent replay
    nullifier: ByteArray,
    /// Midnight state root (currently unused)
    midnight_state_root: ByteArray,
    /// Pricing tier index
    selection: Int,
    /// VPN token owner
    owner: VerificationKeyHash,
    /// VPN region
    region: ByteArray,
    /// User's UTxO for token name derivation
    tx_ref: OutputReference,
  }
  /// Provider withdraws excess funds
  WithdrawExcess { amount: Int }
  /// Provider deposits more funds
  DepositFunds
}

/// Escrow minting redeemer
pub type EscrowMintAction {
  /// Mint nullifier token (one per proof)
  MintNullifier { nullifier: ByteArray }
  /// Mint escrow config NFT (one-shot)
  MintConfigNFT
  /// Burn nullifier or config
  Burn
}
