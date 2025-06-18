use aiken/collection/dict.{empty, insert}
use aiken/collection/list.{any, find}
use cardano/assets.{AssetName, PolicyId, Value, policies, tokens}
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
