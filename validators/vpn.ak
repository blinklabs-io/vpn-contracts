use aiken/collection/list.{any, at, has}
use aiken/option.{is_none}
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId, policies, quantity_of}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction, find_input,
}
use types.{
  BurnVPNAccess, ExtendVPNAccess, MintVPNAccess, Pricing, UpdateReferenceData,
  VPNAction, VPNData, VPNDatum, VPNReferenceData,
}
use utilities.{
  ada_paid_to, get_expiration_time_extend, get_now, get_ref_datum,
  get_script_hash_from_address, get_vkey_hash_from_address, has_vpn_data_output,
  only_2_tokens, output_reference_to_tn, policy_id_present_in_output,
  policy_id_present_in_outputs, quantity_is_one, single_mint,
}

validator vpn(
  wait_time: Int,
  reference_policy_id: PolicyId,
  provider_address: Address,
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
        let token_name = output_reference_to_tn(tx_ref)
        let is_single_mint = single_mint(mint, policy_id, token_name, 1)?
        let correct_region = has(regions, region)?
        let provider_paid = ada_paid_to(outputs, provider_address, price)?
        let owner_signed = has(extra_signatories, owner)?
        let input_consumed =
          any(inputs, fn(input) { input.output_reference == tx_ref })?
        let correct_output =
          has_vpn_data_output(
            outputs,
            Address(Script(policy_id), provider_address.stake_credential),
            policy_id,
            token_name,
            VPNData(owner, region, get_now(validity_range) + duration),
          )?
        is_single_mint? && correct_region? && provider_paid? && owner_signed? && input_consumed? && correct_output?
      }

      BurnVPNAccess { .. } -> {
        let tokens_are_burn =
          !policy_id_present_in_outputs(tx.outputs, policy_id)
        tokens_are_burn?
      }
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
        let Transaction { inputs, outputs, extra_signatories, .. } = tx
        expect Some(own_input) = find_input(inputs, output_reference)
        let provider_signed =
          has(extra_signatories, get_vkey_hash_from_address(provider_address))
        let ref_policy_present_input =
          policy_id_present_in_output(own_input.output, reference_policy_id)
        let ref_policy_output_valid =
          any(
            outputs,
            fn(output) {
              own_input.output.address == output.address && output.datum == InlineDatum(
                VPNReferenceData(pricing, regions),
              ) && policy_id_present_in_output(output, reference_policy_id) && only_2_tokens(
                output.value,
              ) && is_none(output.reference_script)
            },
          )
        let ref_policy_burned = policies(tx.mint) == [reference_policy_id]

        provider_signed? && ref_policy_present_input? && (
          ref_policy_output_valid || ref_policy_burned
        )
      }

      ExtendVPNAccess { new_owner, token_name, selection } -> {
        let Transaction {
          inputs,
          reference_inputs,
          outputs,
          validity_range,
          extra_signatories,
          ..
        } = tx
        expect Some(own_input) = find_input(inputs, output_reference)

        expect Some(VPNData { owner, region, expiration_time }) = opt_datum
        let own_policy_id =
          get_script_hash_from_address(own_input.output.address)
        let owner_pkh =
          if !(new_owner == "") {
            if has(extra_signatories, owner) {
              new_owner
            } else {
              fail
            }
          } else {
            owner
          }

        let new_ex_time =
          if selection > -1 {
            get_expiration_time_extend(
              selection,
              reference_inputs,
              reference_policy_id,
              outputs,
              provider_address,
              get_now(validity_range),
              expiration_time,
            )
          } else {
            expiration_time
          }

        let correct_output =
          has_vpn_data_output(
            outputs,
            own_input.output.address,
            own_policy_id,
            token_name,
            VPNData(owner_pkh, region, new_ex_time),
          )
        let own_token_input =
          quantity_is_one(own_input.output.value, own_policy_id, token_name)
        own_token_input? && correct_output?
      }

      BurnVPNAccess { token_name } -> {
        let Transaction { inputs, mint, validity_range, extra_signatories, .. } =
          tx
        expect Some(own_input) = find_input(inputs, output_reference)
        expect Some(VPNData { owner, expiration_time, .. }) = opt_datum
        let now = get_now(validity_range)
        let own_policy_id =
          get_script_hash_from_address(own_input.output.address)
        let own_token_input =
          quantity_is_one(own_input.output.value, own_policy_id, token_name)
        let is_burned = quantity_of(mint, own_policy_id, token_name) == -1
        let owner_signed =
          now > expiration_time && has(extra_signatories, owner)
        let provider_signed =
          now > expiration_time + wait_time && has(
            extra_signatories,
            get_vkey_hash_from_address(provider_address),
          )
        own_token_input? && is_burned? && ( owner_signed? || provider_signed? )
      }

      _ -> fail @"wrong spending redeemer"
    }
  }

  else(_) {
    fail
  }
}
