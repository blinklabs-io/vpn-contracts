use aiken/builtin.{snd_pair}
use aiken/collection/dict.{empty, insert, size, to_pairs}
use aiken/collection/list.{any, find}
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{
  AssetName, PolicyId, Value, policies, to_dict, tokens, without_lovelace,
}
use cardano/transaction.{Input, Output}

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

/// Find an input which has a specific policy id in his value.
/// Fails if no input found.
pub fn find_input_with_policy(inputs: List<Input>, policy_id: PolicyId) -> Input {
  when
    find(
      inputs,
      fn(input) { policy_id_present_in_output(input.output, policy_id) },
    )
  is {
    Some(input) -> input
    _ -> fail @"no input with that policy id"
  }
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

// get the payment script hash of an address
pub fn get_script_hash_from_address(address: Address) -> ByteArray {
  expect Script(script_hash) = address.payment_credential
  script_hash
}

// get the payment pub key hash of an address
pub fn get_pub_key_hash_from_address(address: Address) -> ByteArray {
  expect VerificationKey(pub_key_hash) = address.payment_credential
  pub_key_hash
}
