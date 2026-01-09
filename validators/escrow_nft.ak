use aiken/collection/list.{any}
use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{OutputReference, Transaction}
use utilities.{single_value}

/// One-shot NFT for escrow configuration
/// Parameterized by the UTxO to consume (ensures uniqueness)
validator escrow_nft(output_reference: OutputReference) {
  mint(redeemer: AssetName, policy_id: PolicyId, tx: Transaction) {
    let Transaction { inputs, mint, .. } = tx
    // Mint: consume specific UTxO
    // Burn: no UTxO check needed
    any(inputs, fn(input) { input.output_reference == output_reference })? && single_value(
      mint,
      policy_id,
      redeemer,
      1,
    )? || single_value(mint, policy_id, redeemer, -1)?
  }

  else(_) {
    fail
  }
}
