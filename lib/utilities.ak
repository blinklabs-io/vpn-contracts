use aiken/builtin.{
  head_list, integer_to_bytearray, snd_pair, unconstr_fields, unconstr_index,
}
use aiken/collection/dict.{empty, insert, size, to_pairs}
use aiken/collection/list.{any, at, find}
use aiken/crypto.{blake2b_256}
use aiken/interval.{Finite, IntervalBound}
use aiken/option.{is_none}
use aiken/primitive/bytearray.{concat}
use cardano/address.{Address, Script}
use cardano/assets.{
  AssetName, PolicyId, Value, from_lovelace, policies, quantity_of, to_dict,
  tokens, without_lovelace,
}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, ValidityRange,
}
use types.{Pricing, VPNDatum}

pub fn get_expiration_time_extend(
  selection: Int,
  reference_inputs: List<Input>,
  reference_policy_id: PolicyId,
  outputs: List<Output>,
  provider_addr: Address,
  now: Int,
  expiration_time: Int,
) -> Int {
  expect pricing: List<Pricing> =
    head_list(
      unconstr_fields(get_ref_datum(reference_inputs, reference_policy_id)),
    )
  expect Some(Pricing { duration, price }) = at(pricing, selection)
  let provider_paid = ada_paid_to(outputs, provider_addr, price)
  if now < expiration_time && provider_paid {
    expiration_time + duration
  } else if provider_paid {
    now + duration
  } else {
    fail
  }
}

pub fn output_reference_to_tn(output_reference: OutputReference) -> ByteArray {
  blake2b_256(
    concat(
      output_reference.transaction_id,
      integer_to_bytearray(False, 0, output_reference.output_index),
    ),
  )
}

pub fn get_ref_datum(reference_inputs: List<Input>, policy_id: PolicyId) -> Data {
  when
    find(
      reference_inputs,
      fn(input) { policy_id_present_in_output(input.output, policy_id) },
    )
  is {
    Some(input) -> head_list(unconstr_fields(input.output.datum))
    _ -> fail @"no input with that policy id"
  }
}

pub fn get_now(validity_range: ValidityRange) -> Int {
  expect IntervalBound { bound_type: Finite(now), .. } =
    validity_range.lower_bound
  now
}

pub fn ada_paid_to(outputs: List<Output>, receiver: Address, am: Int) {
  any(
    outputs,
    fn(output) {
      (output.address == receiver)? && output.value == from_lovelace(am) && unconstr_index(
        output.datum,
      ) == 0 && is_none(output.reference_script)?
    },
  )
}

pub fn has_vpn_data_output(
  outputs: List<Output>,
  out_addr: Address,
  policy_id: PolicyId,
  token_name: AssetName,
  vpn_data: VPNDatum,
) {
  any(
    outputs,
    fn(output) {
      (output.address == out_addr)? && quantity_is_one(
        output.value,
        policy_id,
        token_name,
      )? && (output.datum == InlineDatum(vpn_data))? && only_2_tokens(
        output.value,
      )?
    },
  )
}

pub fn single_mint(value: Value, cs: PolicyId, tn: AssetName, am: Int) -> Bool {
  insert(empty, tn, am) == tokens(value, cs)
}

/// Check if a policy id is present in an output
pub fn policy_id_present_in_output(output: Output, policy_id: PolicyId) -> Bool {
  output.value
    |> policies
    |> any(fn(n) { n == policy_id })
}

/// Check if a policy id is present in a list of outputs
pub fn policy_id_present_in_outputs(
  outputs: List<Output>,
  policy_id: PolicyId,
) -> Bool {
  any(outputs, fn(output) { policy_id_present_in_output(output, policy_id) })
}

/// check there are exactly 2 assets in an value
/// used if exactly ada and a token should be in a value
pub fn only_2_tokens(value: Value) -> Bool {
  when
    value
      |> without_lovelace
      |> to_dict
      |> to_pairs
  is {
    [tnams] ->
      (
        tnams
          |> snd_pair
          |> size
      ) == 1
    _ -> False
  }
}

pub fn quantity_is_one(
  value: Value,
  policy_id: PolicyId,
  asset_name: AssetName,
) -> Bool {
  quantity_of(value, policy_id, asset_name) == 1
}

// get the payment script hash of an address
pub fn get_script_hash_from_address(address: Address) -> ByteArray {
  expect Script(script_hash) = address.payment_credential
  script_hash
}
