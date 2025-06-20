use aiken/collection/dict.{values}
use aiken/collection/list.{all, any, at, has}
use aiken/interval.{Finite, IntervalBound}
use cardano/address.{Address, Script, StakeCredential}
use cardano/assets.{PolicyId, lovelace_of, quantity_of, tokens}
use cardano/transaction.{InlineDatum, OutputReference, Transaction, find_input}
use types.{
  BurnVPNAccess, ExtendVPNAccess, MintVPNAccess, UpdateReferenceData, VPNAction,
  VPNData, VPNDatum, VPNReferenceData,
}
use utilities.{
  find_input_with_policy, get_pub_key_hash_from_address,
  get_script_hash_from_address, only_2_tokens, policy_id_present_in_output,
  single_mint,
}

validator vpn(
  reference_policy_id: PolicyId,
  stake_cred: StakeCredential,
  provider: Address,
) {
  mint(redeemer: VPNAction, policy_id: PolicyId, tx: Transaction) {
    when redeemer is {
      MintVPNAccess { owner, region, selection } -> {
        let Transaction {
          reference_inputs,
          outputs,
          mint,
          validity_range,
          extra_signatories,
          id,
          ..
        } = tx
        expect InlineDatum(datum) =
          find_input_with_policy(reference_inputs, reference_policy_id).output.datum
        expect VPNReferenceData { pricing, regions } = datum
        expect IntervalBound { bound_type: Finite(now), .. } =
          validity_range.lower_bound
        expect Some(Pair(duration, price)) = at(pricing, selection)
        single_mint(mint, policy_id, id, 1) && has(regions, region) && any(
          outputs,
          fn(output) {
            output.address == Address(Script(policy_id), Some(stake_cred)) && quantity_of(
              output.value,
              policy_id,
              id,
            ) == 1 && output.datum == InlineDatum(
              VPNData(owner, region, now + duration),
            ) && only_2_tokens(output.value)
          },
        ) && any(
          outputs,
          fn(output) {
            output.address == provider && lovelace_of(output.value) >= price && only_2_tokens(
              output.value,
            )
          },
        ) && has(extra_signatories, owner)
      }
      BurnVPNAccess ->
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
        has(tx.extra_signatories, get_pub_key_hash_from_address(provider)) && any(
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
        expect InlineDatum(ref_datum) =
          find_input_with_policy(reference_inputs, reference_policy_id).output.datum
        expect VPNReferenceData { pricing, .. } = ref_datum
        expect VPNData { owner, region, expiration_time } = datum
        expect Some(Pair(duration, price)) = at(pricing, selection)
        expect IntervalBound { bound_type: Finite(now), .. } =
          validity_range.lower_bound
        let own_policy_id =
          get_script_hash_from_address(own_input.output.address)
        let owner_pkh =
          when maybe_new_owner is {
            Some(pkh) -> pkh
            None -> owner
          }
        quantity_of(own_input.output.value, own_policy_id, token_name) == 1 && any(
          outputs,
          fn(output) {
            output.address == own_input.output.address && quantity_of(
              output.value,
              own_policy_id,
              token_name,
            ) == 1 && output.datum == InlineDatum(
              VPNData(
                owner_pkh,
                region,
                if now < expiration_time {
                  expiration_time + duration
                } else {
                  now + duration
                },
              ),
            ) && only_2_tokens(output.value)
          },
        ) && any(
          outputs,
          fn(output) {
            output.address == provider && lovelace_of(output.value) >= price && only_2_tokens(
              output.value,
            )
          },
        ) && when maybe_new_owner is {
          Some(pkh) ->
            has(extra_signatories, pkh) && has(extra_signatories, owner)
          None -> has(extra_signatories, owner)
        }
      }

      BurnVPNAccess -> True
      _ -> fail @"wrong spending redeemer"
    }
  }

  else(_) {
    fail
  }
}
