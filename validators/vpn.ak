use aiken/builtin.{integer_to_bytearray}
use aiken/collection/dict.{values}
use aiken/collection/list.{all, any, at, has}
use aiken/crypto.{VerificationKeyHash, blake2b_256}
use aiken/interval.{Finite, IntervalBound, is_entirely_after}
use aiken/option.{is_none}
use aiken/primitive/bytearray.{concat}
use cardano/address.{Address, Script, StakeCredential, VerificationKey}
use cardano/assets.{
  AssetName, PolicyId, lovelace_of, quantity_of, tokens, without_lovelace, zero,
}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction, ValidityRange,
  find_input,
}
use types.{
  BurnVPNAccess, ExtendVPNAccess, MintVPNAccess, Pricing, UpdateReferenceData,
  VPNAction, VPNData, VPNDatum, VPNReferenceData,
}
use utilities.{
  find_input_with_policy, get_script_hash_from_address, only_2_tokens,
  policy_id_present_in_output, policy_id_present_in_outputs, single_mint,
}

fn ada_paid_to(outputs: List<Output>, receiver: Address, am: Int) {
  trace @"ada_paid_to"
  any(
    outputs,
    fn(output) {
      (output.address == receiver)? && (lovelace_of(output.value) >= am)? && (without_lovelace(
        output.value,
      ) == zero)? && is_none(output.reference_script)?
    },
  )
}

fn has_vpn_data_output(
  outputs: List<Output>,
  out_addr: Address,
  policy_id: PolicyId,
  token_name: AssetName,
  vpn_data: VPNDatum,
) {
  any(
    outputs,
    fn(output) {
      (output.address == out_addr)? && (quantity_of(
        output.value,
        policy_id,
        token_name,
      ) == 1)? && (output.datum == InlineDatum(vpn_data))? && only_2_tokens(
        output.value,
      )?
    },
  )
}

fn get_ref_datum(reference_inputs: List<Input>, policy_id: PolicyId) -> Data {
  expect InlineDatum(datum) =
    find_input_with_policy(reference_inputs, policy_id).output.datum
  datum
}

fn get_now(validity_range: ValidityRange) -> Int {
  expect IntervalBound { bound_type: Finite(now), .. } =
    validity_range.lower_bound
  now
}

validator vpn(
  wait_time: Int,
  reference_policy_id: PolicyId,
  provider_pkh: VerificationKeyHash,
  provider_stake_pkh: StakeCredential,
) {
  mint(redeemer: VPNAction, policy_id: PolicyId, tx: Transaction) {
    when redeemer is {
      MintVPNAccess { owner, region, selection, tx_ref } -> {
        let Transaction {
          inputs,
          reference_inputs,
          outputs,
          mint,
          validity_range,
          extra_signatories,
          ..
        } = tx
        expect VPNReferenceData { pricing, regions } =
          get_ref_datum(reference_inputs, reference_policy_id)
        expect Some(Pricing { duration, price }) = at(pricing, selection)
        let provider_addr =
          Address(VerificationKey(provider_pkh), Some(provider_stake_pkh))
        let own_addr = Address(Script(policy_id), Some(provider_stake_pkh))
        let token_name =
          blake2b_256(
            concat(
              tx_ref.transaction_id,
              integer_to_bytearray(False, 0, tx_ref.output_index),
            ),
          )
        single_mint(mint, policy_id, token_name, 1)? && has(regions, region)? && has_vpn_data_output(
          outputs,
          own_addr,
          policy_id,
          token_name,
          VPNData(owner, region, get_now(validity_range) + duration),
        )? && ada_paid_to(outputs, provider_addr, price)? && has(
          extra_signatories,
          owner,
        )? && any(inputs, fn(input) { input.output_reference == tx_ref })?
      }
      BurnVPNAccess(_) ->
        all(values(tokens(tx.mint, policy_id)), fn(am) { am == -1 })
      _ -> fail @"wrong minting redeemer"
    }
  }

  spend(
    opt_datum: Option<VPNDatum>,
    redeemer: VPNAction,
    output_reference: OutputReference,
    tx: Transaction,
  ) {
    when redeemer is {
      UpdateReferenceData { pricing, regions } -> {
        expect Some(own_input) = find_input(tx.inputs, output_reference)
        has(tx.extra_signatories, provider_pkh) && any(
          tx.outputs,
          fn(output) {
            own_input.output.address == output.address && output.datum == InlineDatum(
              VPNReferenceData(pricing, regions),
            ) && policy_id_present_in_output(output, reference_policy_id) && only_2_tokens(
              output.value,
            )
          },
        ) && policy_id_present_in_output(own_input.output, reference_policy_id)
      }
      ExtendVPNAccess { maybe_new_owner, token_name, selection } -> {
        let Transaction {
          inputs,
          reference_inputs,
          outputs,
          validity_range,
          extra_signatories,
          ..
        } = tx
        expect Some(own_input) = find_input(inputs, output_reference)
        expect Some(datum) = opt_datum
        expect VPNReferenceData { pricing, .. } =
          get_ref_datum(reference_inputs, reference_policy_id)
        expect VPNData { owner, region, expiration_time } = datum
        expect Some(Pricing { duration, price }) = at(pricing, selection)
        let now = get_now(validity_range)
        let own_policy_id =
          get_script_hash_from_address(own_input.output.address)
        let owner_pkh =
          when maybe_new_owner is {
            Some(pkh) ->
              if has(extra_signatories, pkh) && has(extra_signatories, owner) {
                pkh
              } else {
                fail
              }
            None ->
              if has(extra_signatories, owner) {
                owner
              } else {
                fail
              }
          }
        let vpn_data =
          VPNData(
            owner_pkh,
            region,
            if now > expiration_time {
              expiration_time + duration
            } else {
              now + duration
            },
          )
        let provider_addr =
          Address(VerificationKey(provider_pkh), Some(provider_stake_pkh))
        has_vpn_data_output(
          outputs,
          own_input.output.address,
          own_policy_id,
          token_name,
          vpn_data,
        ) && quantity_of(own_input.output.value, own_policy_id, token_name) == 1 && ada_paid_to(
          outputs,
          provider_addr,
          price,
        )
      }

      BurnVPNAccess(token_name) -> {
        let Transaction {
          inputs,
          outputs,
          validity_range,
          extra_signatories,
          ..
        } = tx
        expect Some(own_input) = find_input(inputs, output_reference)
        expect Some(datum) = opt_datum
        expect VPNData { owner, expiration_time, .. } = datum
        let own_policy_id =
          get_script_hash_from_address(own_input.output.address)
        quantity_of(own_input.output.value, own_policy_id, token_name) == 1 && policy_id_present_in_outputs(
          outputs,
          own_policy_id,
        ) == False && (
          is_entirely_after(validity_range, expiration_time) && has(
            extra_signatories,
            owner,
          ) || is_entirely_after(validity_range, expiration_time + wait_time) && has(
            extra_signatories,
            provider_pkh,
          )
        )
      }

      _ -> fail @"wrong spending redeemer"
    }
  }

  else(_) {
    fail
  }
}
