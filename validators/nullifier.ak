use aiken/collection/list.{any}
use cardano/assets.{PolicyId, policies, quantity_of}
use cardano/transaction.{Transaction}
use utilities.{single_value}

/// Nullifier Registry Contract
///
/// This validator manages nullifier tokens that track used Midnight ZK proofs.
/// Each nullifier is a unique 32-byte hash derived from the Midnight payment proof.
/// Minting a nullifier token marks the proof as "used" to prevent replay attacks.
///
/// Design:
/// - Nullifiers can only be minted when a VPN token is also being minted
/// - This ensures nullifiers are only created during valid MintVPNAccessWithProof transactions
/// - The VPN policy ID is a parameter set at deployment time
/// - Only single mints are allowed (one nullifier per proof)
///
/// Parameters:
/// - vpn_policy_id: The policy ID of the VPN token minting validator

validator nullifier(vpn_policy_id: PolicyId) {
  /// Mint handler for nullifier tokens
  ///
  /// A nullifier can be minted when:
  /// 1. A VPN token is being minted in the same transaction (vpn_minting)
  /// 2. Exactly one nullifier token is being minted (single_mint)
  ///
  /// This ties nullifier creation to valid VPN minting operations,
  /// preventing arbitrary nullifier creation.
  mint(nullifier_hash: ByteArray, policy_id: PolicyId, tx: Transaction) {
    let Transaction { mint, .. } = tx

    // Check that VPN tokens are being minted in this transaction
    // This ensures nullifiers are only created during MintVPNAccessWithProof
    let vpn_minting =
      mint
        |> policies
        |> any(fn(p) { p == vpn_policy_id })

    // Check that exactly one nullifier token is being minted
    // The token name is the nullifier hash from the ZK proof
    let single_mint = single_value(mint, policy_id, nullifier_hash, 1)

    vpn_minting? && single_mint?
  }

  /// Spend handler - nullifiers should never be spent
  /// They are permanent records of used proofs
  spend(_datum, _redeemer, _output_ref, _tx) {
    fail @"nullifier tokens cannot be spent"
  }

  /// Fallback - reject all other operations
  else(_) {
    fail
  }
}
