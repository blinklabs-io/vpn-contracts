use aiken/builtin.{head_list, unconstr_fields}
use aiken/collection/dict.{values}
use aiken/collection/list.{all, any, at, has}
use aiken/crypto.{VerificationKeyHash}
use aiken/option.{is_none}
use cardano/address.{Address, Script, StakeCredential, VerificationKey}
use cardano/assets.{PolicyId, policies, tokens}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction, find_input,
}
use types.{
  BurnVPNAccess, ExtendVPNAccess, MintVPNAccess, Pricing, UpdateReferenceData,
  VPNAction, VPNData, VPNDatum, VPNReferenceData,
}
use utilities.{
  ada_paid_to, get_now, get_ref_datum, get_script_hash_from_address,
  has_vpn_data_output, only_2_tokens, output_reference_to_tn,
  policy_id_present_in_output, policy_id_present_in_outputs, quantity_is_one,
  single_mint,
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
        let token_name = output_reference_to_tn(tx_ref)

        single_mint(mint, policy_id, token_name, 1)? && has(regions, region)? && has_vpn_data_output(
          outputs,
          Address(Script(policy_id), Some(provider_stake_pkh)),
          policy_id,
          token_name,
          VPNData(owner, region, get_now(validity_range) + duration),
        )? && ada_paid_to(
          outputs,
          Address(VerificationKey(provider_pkh), Some(provider_stake_pkh)),
          price,
        )? && has(extra_signatories, owner)? && any(
          inputs,
          fn(input) { input.output_reference == tx_ref },
        )?
      }
      BurnVPNAccess { .. } ->
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
        let Transaction { inputs, outputs, extra_signatories, .. } = tx
        expect Some(own_input) = find_input(inputs, output_reference)
        has(extra_signatories, provider_pkh) && policy_id_present_in_output(
          own_input.output,
          reference_policy_id,
        ) && (
          any(
            outputs,
            fn(output) {
              own_input.output.address == output.address && output.datum == InlineDatum(
                VPNReferenceData(pricing, regions),
              ) && policy_id_present_in_output(output, reference_policy_id) && only_2_tokens(
                output.value,
              ) && is_none(output.reference_script)
            },
          ) || policies(tx.mint) == [reference_policy_id]
        )
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
        expect pricing: List<Pricing> =
          head_list(
            unconstr_fields(
              get_ref_datum(reference_inputs, reference_policy_id),
            ),
          )
        expect Some(VPNData { owner, region, expiration_time }) = opt_datum
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

        has_vpn_data_output(
          outputs,
          own_input.output.address,
          own_policy_id,
          token_name,
          vpn_data,
        ) && quantity_is_one(own_input.output.value, own_policy_id, token_name) && ada_paid_to(
          outputs,
          Address(VerificationKey(provider_pkh), Some(provider_stake_pkh)),
          price,
        )
      }

      BurnVPNAccess { token_name } -> {
        let Transaction {
          inputs,
          outputs,
          validity_range,
          extra_signatories,
          ..
        } = tx
        expect Some(own_input) = find_input(inputs, output_reference)
        expect Some(VPNData { owner, expiration_time, .. }) = opt_datum
        let now = get_now(validity_range)
        let own_policy_id =
          get_script_hash_from_address(own_input.output.address)

        quantity_is_one(own_input.output.value, own_policy_id, token_name) && !policy_id_present_in_outputs(
          outputs,
          own_policy_id,
        ) && (
          now > expiration_time && has(extra_signatories, owner) || now > expiration_time + wait_time && has(
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
