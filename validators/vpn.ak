use aiken/collection/dict.{values}
use aiken/collection/list.{all, any, at, has}
use aiken/interval.{Finite, IntervalBound}
use cardano/address.{Address, Script, StakeCredential}
use cardano/assets.{PolicyId, lovelace_of, quantity_of, tokens}
use cardano/transaction.{InlineDatum, OutputReference, Transaction}
use types.{
  BurnVPNAccess, ExtendVPNAccess, MintVPNAccess, Reimburse, UnlockPayment,
  UpdateReferenceData, VPNAction, VPNData, VPNDatum, VPNReferenceData,
}
use utilities.{find_input_with_policy, single_mint}

validator vpn(
  reference_policy_id: PolicyId,
  stake_cred: StakeCredential,
  _provider: Address,
) {
  mint(redeemer: VPNAction, policy_id: PolicyId, tx: Transaction) {
    when redeemer is {
      MintVPNAccess { owner, region, selection } -> {
        let Transaction {
          reference_inputs,
          outputs,
          mint,
          validity_range,
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
            ) && lovelace_of(output.value) == price + 2000000
          },
        )
      }
      BurnVPNAccess ->
        all(values(tokens(tx.mint, policy_id)), fn(am) { am == -1 })
      _ -> fail @"wrong minting redeemer"
    }
  }

  spend(
    _datum: Option<VPNDatum>,
    redeemer: VPNAction,
    _output_reference: OutputReference,
    _tx: Transaction,
  ) {
    when redeemer is {
      UpdateReferenceData -> True
      ExtendVPNAccess -> True
      Reimburse -> True
      UnlockPayment -> True
      BurnVPNAccess -> True
      _ -> fail @"wrong spending redeemer"
    }
  }

  else(_) {
    fail
  }
}
