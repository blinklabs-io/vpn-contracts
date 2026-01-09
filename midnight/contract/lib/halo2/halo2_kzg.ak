use aiken/collection/list.{
  concat, foldl, foldl2, head, is_empty, last, length, map, map2, map3, push,
  range, reverse, zip,
}
use aiken/crypto/bls12_381/g1.{add as add_g1, compress, decompress, scale, zero}
use aiken/crypto/bls12_381/scalar.{Scalar, add, mul, sub}
use halo2/compat.{State, foldr2, from_int}
use halo2/lagrange.{batch_inverses, lagrange_evaluation}
use halo2/verifier_key.{neg_g1_generator}

// Computes MSM for verifying multiple openings in the KZG polynomial commitment scheme (the multi-open protocol from the Halo2 book).
// It represents the `right` input to the pairing check equation: `e(left, sG2) == e(right, G2)`,
// where `left` is PI commitment.
// For reference implementation, see `https://github.com/input-output-hk/halo2/blob/plutus_verification/src/poly/kzg/mod.rs#L193`

pub fn compute_msm(
  x1Powers: List<State<Scalar>>,
  x2: State<Scalar>,
  x3: State<Scalar>,
  x4Powers: List<State<Scalar>>,
  f_commitment: ByteArray,
  pi_commitment: ByteArray,
  proofX3QEvals: List<State<Scalar>>,
  commitmentMap: List<List<(ByteArray, List<State<Scalar>>)>>,
  pointSets: List<List<State<Scalar>>>,
) -> G1Element {
  trace @"msm x3": x3
  let
    final_com,
    q_eval_sets,
  <-
    compute_q_evals_and_final_comm(
      commitmentMap,
      x1Powers,
      x4Powers,
      f_commitment,
    )

  trace @"msm final_com": compress(final_com)
  let f_eval = compute_f_eval(pointSets, q_eval_sets, x2, x3, proofX3QEvals)
  trace @"msm f_eval": f_eval
  let v = compute_v(f_eval, x4Powers, proofX3QEvals)
  trace @"msm v": v

  // Trace intermediate values
  let neg_g1_scaled = scale(decompress(neg_g1_generator), v)
  trace @"msm neg_g1_scaled": compress(neg_g1_scaled)
  let pi_scaled = scale(decompress(pi_commitment), x3)
  trace @"msm pi_scaled": compress(pi_scaled)
  let result = add_g1(final_com, add_g1(neg_g1_scaled, pi_scaled))
  trace @"msm result (er)": compress(result)

  result
}

fn compute_q_evals_and_final_comm(
  commitmentMap: List<List<(ByteArray, List<State<Scalar>>)>>,
  x1Powers: List<State<Scalar>>,
  x4Powers: List<State<Scalar>>,
  f_commitment: ByteArray,
  continue: fn(G1Element, List<List<State<Scalar>>>) -> a,
) -> a {
  trace @"compute_q_evals: num commitment sets": length(commitmentMap)
  trace @"compute_q_evals: x1Powers count": length(x1Powers)
  trace @"compute_q_evals: x4Powers count": length(x4Powers)

  let
    final_comm,
    q_eval_sets,
  <-
    foldr2(
      zip(commitmentMap, x4Powers),
      zero,
      [],
      fn((commitments_for_set, x4Power), acc1, acc2, return) {
        trace @"processing set with commitments": length(commitments_for_set)
        // Use regular foldl instead of CPS foldl2 to ensure correct left-to-right order
        let (q_comms, eval_set, iter) =
          foldl(
            zip(x1Powers, commitments_for_set),
            (zero, [], 0),
            fn((x1Power, (commitment, es)), (acc1, acc2, i)) {
              expect Some(e_first) = head(es)
              trace @"commitment iter": i
              trace @"x1Power": x1Power
              trace @"eval first": e_first
              let new_acc1 =
                add_g1(acc1, scale(decompress(commitment), x1Power))
              let new_acc2 =
                if is_empty(acc2) {
                  map(es, fn(e) { mul(e, x1Power) })
                } else {
                  map2(acc2, es, fn(a, b) { add(a, mul(b, x1Power)) })
                }
              (new_acc1, new_acc2, i + 1)
            },
          )

        trace @"eval_set for this query set": eval_set
        // scale Q commitments by x4Powers and accumulate them in final commitment
        let acc1 = add_g1(acc1, scale(q_comms, x4Power))
        let acc2 = push(acc2, eval_set)
        return(acc1, acc2)
      },
    )

  trace @"q_eval_sets computed - length": length(q_eval_sets)
  // Trace first element of each eval_set
  expect [qs0, qs1, qs2] = q_eval_sets
  trace @"q_eval_sets[0] length": length(qs0)
  trace @"q_eval_sets[1] length": length(qs1)
  trace @"q_eval_sets[2] length": length(qs2)
  expect Some(qs0_first) = head(qs0)
  expect Some(qs1_first) = head(qs1)
  expect Some(qs2_first) = head(qs2)
  trace @"q_eval_sets[0][0] (should be 1-rot weighted sum)": qs0_first
  trace @"q_eval_sets[1][0] (should be 3-rot weighted sum at x)": qs1_first
  trace @"q_eval_sets[2][0] (should be 2-rot weighted sum at x)": qs2_first
  // We also need to add the f_commitment scaled by the last x4Power
  expect Some(x4Power) = last(x4Powers)
  let final_comm = add_g1(final_comm, scale(decompress(f_commitment), x4Power))

  // Note: foldr2 processes right-to-left, but Aiken's push PREPENDS (adds to front),
  // so the final order is [1-rot, 3-rot, 2-rot] which matches point_sets. No reverse needed.
  continue(final_comm, q_eval_sets)
}

// TODO: Revert to this version of `compute_f_eval` when CIP-109 with built-in inverse is available, 
//       because it will be faster than batch_inverses
// pub fn compute_f_eval(
//   point_sets: List<List<State<Scalar>>>,
//   q_eval_sets: List<List<State<Scalar>>>,
//   x2: State<Scalar>,
//   x3: State<Scalar>,
//   proof_X3_q_evals: List<State<Scalar>>,
// ) -> State<Scalar> {
//   foldl(
//     reverse(zip(point_sets, zip(q_eval_sets, proof_X3_q_evals))),
//     from_int(0),
//     fn((points, (evals, proofQEval)), acc_eval) {
//       let r_eval = lagrange_evaluation(zip(points, evals), x3)
//       let denominator =
//         recip(
//           foldl(
//             points,
//             from_int(1),
//             fn(point, acc) { mul(acc, sub(x3, point)) },
//           ),
//         )
//       let evaluation = mul(sub(proofQEval, r_eval), denominator)

//       add(mul(acc_eval, x2), evaluation)
//     },
//   )
// }

// Optimized with batch_inverses - replaces N recip_eea calls with 1
pub fn compute_f_eval(
  point_sets: List<List<State<Scalar>>>,
  q_eval_sets: List<List<State<Scalar>>>,
  x2: State<Scalar>,
  x3: State<Scalar>,
  proof_X3_q_evals: List<State<Scalar>>,
) -> State<Scalar> {
  trace @"compute_f_eval: num point_sets": length(point_sets)
  trace @"compute_f_eval: x2": x2
  trace @"compute_f_eval: x3": x3

  // Step 1: Compute r_evals and denominators for all point sets (no inversions yet)
  let data =
    map3(
      point_sets,
      q_eval_sets,
      proof_X3_q_evals,
      fn(points, evals, proofQEval) {
        let r_eval = lagrange_evaluation(zip(points, evals), x3)
        let denom =
          foldl(
            points,
            from_int(1),
            fn(point, acc) { mul(acc, sub(x3, point)) },
          )
        trace @"compute_f_eval: point set size": length(points)
        trace @"compute_f_eval: r_eval": r_eval
        trace @"compute_f_eval: proofQEval": proofQEval
        trace @"compute_f_eval: denom": denom
        (r_eval, denom, proofQEval)
      },
    )

  // Step 2: Extract denominators and batch invert (1 recip instead of N)
  let denominators = map(data, fn((_, denom, _)) { denom })
  let inverted_denominators = batch_inverses(denominators)

  // Trace each evaluation term before computing
  let _ =
    foldl(
      zip(zip(data, inverted_denominators), range(0, 2)),
      from_int(0),
      fn((((r_eval, _, proofQEval), denom_inv), idx), acc) {
        let numerator = sub(proofQEval, r_eval)
        let evaluation = mul(numerator, denom_inv)
        trace @"f_eval term idx": idx
        trace @"f_eval term numerator (proofQ - r_eval)": numerator
        trace @"f_eval term denom_inv": denom_inv
        trace @"f_eval term evaluation": evaluation
        acc
      },
    )

  // Step 3: Compute final result with inverted denominators
  // Try both orders to find which matches halo2
  let result_reversed =
    foldl(
      reverse(zip(data, inverted_denominators)),
      from_int(0),
      fn(((r_eval, _, proofQEval), denom_inv), acc_eval) {
        let numerator = sub(proofQEval, r_eval)
        let evaluation = mul(numerator, denom_inv)
        add(mul(acc_eval, x2), evaluation)
      },
    )

  let result_not_reversed =
    foldl(
      zip(data, inverted_denominators),
      from_int(0),
      fn(((r_eval, _, proofQEval), denom_inv), acc_eval) {
        let numerator = sub(proofQEval, r_eval)
        let evaluation = mul(numerator, denom_inv)
        add(mul(acc_eval, x2), evaluation)
      },
    )

  trace @"compute_f_eval: result_reversed (order 3,2,1)": result_reversed
  trace @"compute_f_eval: result_not_reversed (order 1,2,3)": result_not_reversed

  // Horner's method requires processing from highest to lowest power of x2.
  // The polynomial is: f_eval = term_1 + x2*term_2 + x2^2*term_3
  // To compute this via Horner: ((term_3) * x2 + term_2) * x2 + term_1
  // This means we must process in REVERSE order: [3pt, 2pt, 1pt]
  let result = result_reversed

  trace @"compute_f_eval: final result": result
  result
}

fn compute_v(
  f_eval: State<Scalar>,
  x4Powers: List<State<Scalar>>,
  proofX3QEvals: List<State<Scalar>>,
) -> State<Scalar> {
  trace @"compute_v: f_eval": f_eval
  trace @"compute_v: proofX3QEvals count": length(proofX3QEvals)
  trace @"compute_v: x4Powers count": length(x4Powers)

  // Try different orderings to debug
  // Order 1 (original): [q1, q2, q3, f_eval] with [x4^0, x4^1, x4^2, x4^3]
  let evals_order1 = concat(proofX3QEvals, [f_eval])

  // Order 2: [f_eval, q1, q2, q3] - f_eval first
  let evals_order2 = concat([f_eval], proofX3QEvals)

  // Order 3: [q3, q2, q1, f_eval] - reversed q_evals
  let evals_order3 = concat(reverse(proofX3QEvals), [f_eval])

  // Order 4: [f_eval, q3, q2, q1] - f_eval first, reversed q_evals
  let evals_order4 = concat([f_eval], reverse(proofX3QEvals))

  let result1 =
    foldl(
      zip(x4Powers, evals_order1),
      from_int(0),
      fn((p, e), acc) { add(acc, mul(p, e)) },
    )
  let result2 =
    foldl(
      zip(x4Powers, evals_order2),
      from_int(0),
      fn((p, e), acc) { add(acc, mul(p, e)) },
    )
  let result3 =
    foldl(
      zip(x4Powers, evals_order3),
      from_int(0),
      fn((p, e), acc) { add(acc, mul(p, e)) },
    )
  let result4 =
    foldl(
      zip(x4Powers, evals_order4),
      from_int(0),
      fn((p, e), acc) { add(acc, mul(p, e)) },
    )

  trace @"compute_v order1 [q1,q2,q3,f]": result1
  trace @"compute_v order2 [f,q1,q2,q3]": result2
  trace @"compute_v order3 [q3,q2,q1,f]": result3
  trace @"compute_v order4 [f,q3,q2,q1]": result4

  // halo2's expected v from Rust MSM Term 23
  // Check which order matches
  let halo2_v =
    from_int(
      38059411669140381476208425199150651245790857027832311144872660018717239300309,
    )
  trace @"halo2 expected v": halo2_v
  trace @"order1 matches halo2": result1 == halo2_v
  trace @"order2 matches halo2": result2 == halo2_v
  trace @"order3 matches halo2": result3 == halo2_v
  trace @"order4 matches halo2": result4 == halo2_v

  // Compute what f_eval would need to be for order1 to match halo2
  // v = q1 + x4*q2 + x4^2*q3 + x4^3*f_eval
  // f_eval = (v - q1 - x4*q2 - x4^2*q3) / x4^3
  expect [x4_0, x4_1, x4_2, x4_3] = x4Powers
  expect [q1, q2, q3] = proofX3QEvals
  let partial = add(q1, add(mul(x4_1, q2), mul(x4_2, q3)))
  let needed_for_f = sub(halo2_v, partial)
  trace @"partial (q1 + x4*q2 + x4^2*q3)": partial
  trace @"halo2_v - partial (should be x4^3 * f_eval)": needed_for_f
  trace @"x4^3": x4_3

  // Check if our f_eval times x4^3 equals needed_for_f
  let our_f_contrib = mul(x4_3, f_eval)
  trace @"our x4^3 * f_eval": our_f_contrib
  trace @"difference (needed - our)": sub(needed_for_f, our_f_contrib)

  // Return order1 for now (current behavior)
  result1
}
