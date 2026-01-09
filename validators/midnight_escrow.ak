use aiken/builtin
use aiken/collection/list.{any, at, find, has}
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId, quantity_of}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction, find_input,
}
use escrow_types.{
  Burn, DepositFunds, EscrowConfig, EscrowDatum, EscrowMintAction,
  EscrowSpendAction, MintConfigNFT, MintNullifier, ReleaseFunds, WithdrawExcess,
}
use types.{Pricing, VPNReferenceData}
use utilities.{
  ada_paid_to, get_ref_datum, get_vkey_hash_from_address, nullifier_exists,
  output_reference_to_tn, policy_id_present_in_output, single_value,
  verify_midnight_payment,
}

/// Get escrow configuration from reference inputs
fn get_escrow_config(
  reference_inputs: List<Input>,
  escrow_config_policy_id: PolicyId,
) -> EscrowConfig {
  when
    find(
      reference_inputs,
      fn(input) {
        policy_id_present_in_output(input.output, escrow_config_policy_id)
      },
    )
  is {
    Some(input) -> {
      expect InlineDatum(datum) = input.output.datum
      expect config: EscrowConfig = datum
      config
    }
    _ -> fail @"escrow config not found in reference inputs"
  }
}

/// Helper to get script hash from spent output
fn get_script_hash_from_output(
  output_reference: OutputReference,
  inputs: List<Input>,
) -> ByteArray {
  expect Some(Input { output, .. }) = find_input(inputs, output_reference)
  expect Script(script_hash) = output.address.payment_credential
  script_hash
}

/// Midnight escrow validator
/// Handles ZK proof verification and fund release for VPN minting
validator midnight_escrow(
  escrow_config_policy_id: PolicyId,
  vpn_reference_policy_id: PolicyId,
  provider_address: Address,
) {
  /// Mint handler: nullifier tokens and config NFT
  mint(redeemer: EscrowMintAction, policy_id: PolicyId, tx: Transaction) {
    when redeemer is {
      MintNullifier { nullifier } -> {
        // Nullifier must be exactly 32 bytes
        let valid_length = builtin.length_of_bytearray(nullifier) == 32
        // Must mint exactly one nullifier token
        let is_single_mint = single_value(tx.mint, policy_id, nullifier, 1)?
        valid_length? && is_single_mint?
      }
      MintConfigNFT ->
        // Config NFT minting handled by escrow_nft validator
        // This is just for documentation - escrow policy doesn't mint config
        fail @"use escrow_nft validator for config NFT"
      Burn ->
        // Allow burning any token under this policy
        True
    }
  }

  /// Spend handler: release funds or manage escrow
  spend(
    opt_datum: Option<EscrowDatum>,
    redeemer: EscrowSpendAction,
    output_reference: OutputReference,
    tx: Transaction,
  ) {
    expect Some(escrow_datum) = opt_datum
    let EscrowDatum { total_ada, payment_count } = escrow_datum

    when redeemer is {
      ReleaseFunds {
        zk_proof,
        nullifier,
        midnight_state_root,
        selection,
        owner,
        region,
        tx_ref,
      } -> {
        let Transaction {
          inputs,
          reference_inputs,
          outputs,
          mint,
          extra_signatories,
          ..
        } = tx

        // Get configurations
        let EscrowConfig { verifier_hash, midnight_enabled, vpn_policy_id, .. } =
          get_escrow_config(reference_inputs, escrow_config_policy_id)

        // Get VPN pricing for duration calculation
        expect VPNReferenceData { pricing, regions } =
          get_ref_datum(reference_inputs, vpn_reference_policy_id)
        expect Some(Pricing { price, .. }) = at(pricing, selection)

        // Midnight must be enabled
        expect midnight_enabled

        // Verify ZK proof
        let proof_valid =
          verify_midnight_payment(
            verifier_hash,
            zk_proof,
            selection,
            nullifier,
            midnight_state_root,
          )?

        // Check nullifier not already used (check reference inputs for existing nullifier token)
        let escrow_policy_id =
          get_script_hash_from_output(output_reference, inputs)
        let nullifier_fresh =
          !nullifier_exists(reference_inputs, escrow_policy_id, nullifier)?

        // Nullifier must be minted in this transaction
        let nullifier_minted =
          quantity_of(mint, escrow_policy_id, nullifier) == 1

        // VPN token must be minted (via standard MintVPNAccess)
        let vpn_token_name = output_reference_to_tn(tx_ref)
        let vpn_minted = quantity_of(mint, vpn_policy_id, vpn_token_name) == 1

        // Owner must sign
        let owner_signed = has(extra_signatories, owner)?

        // Region must be valid
        let correct_region = has(regions, region)?

        // Provider receives payment (from escrow funds)
        let provider_paid = ada_paid_to(outputs, provider_address, price)?

        // Escrow continuing output with updated state
        expect Some(Input { output: escrow_input, .. }) =
          find_input(inputs, output_reference)
        let escrow_continuing =
          any(
            outputs,
            fn(output) {
              output.address == escrow_input.address && output.datum == InlineDatum(
                EscrowDatum(total_ada - price, payment_count + 1),
              ) && policy_id_present_in_output(output, escrow_config_policy_id)
            },
          )

        proof_valid? && nullifier_fresh? && nullifier_minted? && vpn_minted? && owner_signed? && correct_region? && provider_paid? && escrow_continuing?
      }

      WithdrawExcess { amount } -> {
        let Transaction { inputs, outputs, extra_signatories, .. } = tx
        // Only provider can withdraw
        let provider_signed =
          has(extra_signatories, get_vkey_hash_from_address(provider_address))

        // Escrow must continue with reduced balance
        expect Some(Input { output: escrow_input, .. }) =
          find_input(inputs, output_reference)
        let escrow_continuing =
          any(
            outputs,
            fn(output) {
              output.address == escrow_input.address && output.datum == InlineDatum(
                EscrowDatum(total_ada - amount, payment_count),
              )
            },
          )

        provider_signed? && escrow_continuing?
      }

      DepositFunds -> {
        let Transaction { inputs, outputs, extra_signatories, .. } = tx
        // Only provider can deposit
        let provider_signed =
          has(extra_signatories, get_vkey_hash_from_address(provider_address))

        // Escrow must continue (balance increase tracked via datum)
        expect Some(Input { output: escrow_input, .. }) =
          find_input(inputs, output_reference)
        let escrow_continuing =
          any(
            outputs,
            fn(output) {
              output.address == escrow_input.address && policy_id_present_in_output(
                output,
                escrow_config_policy_id,
              )
            },
          )

        provider_signed? && escrow_continuing?
      }
    }
  }

  else(_) {
    fail
  }
}
