use aiken/collection/list.{foldl, last, take}
use aiken/crypto/bls12_381/g1.{
  add as addG1, compress, decompress, scale as scaleG1, sub as subG1, zero,
}
use aiken/crypto/bls12_381/g2.{
  compress as compress_g2, generator as generatorG2,
}
use aiken/crypto/bls12_381/scalar.{Scalar, add, mul, neg, scale, sub}
use aiken/primitive/bytearray
use halo2/bls_utils.{inner_product, recip_eea}
use halo2/compat.{State, final_exponentiation, from_int, miller_loop}
use halo2/halo2_kzg.{compute_msm}
use halo2/lagrange.{lagrange_polynomial_basis}
use halo2/omega_rotations.{powers, rotate_omega, rotate_omegas}
use halo2/transcript.{
  common_scalar, construct_transcript, read_point, read_scalar,
  squeeze_challenge,
}
use halo2/verifier_key.{
  barycentric_weight, blinding_factors, f1_commitment, f2_commitment,
  f3_commitment, f4_commitment, g2_const, omega, omega_inv, p1_commitment,
  p2_commitment, p3_commitment, p4_commitment, p5_commitment, p6_commitment,
  transcript_rep,
}

pub fn verifier(proof: Data, i_1: State<Scalar>, i_2: State<Scalar>) -> Bool {
  let rotations_for_vanishing =
    rotate_omegas(omega, omega_inv, -(blinding_factors + 1), 0)

  let scalarZero = from_int(0)
  let scalarOne = from_int(1)
  let scalarDelta =
    from_int(0x8634d0aa021aaf843cab354fabb0062f6502437c6a09c006c083479590189d7)

  let inputs_count = from_int(2)

  let transcript = construct_transcript(proof, transcript_rep)
  let transcript = common_scalar(inputs_count, transcript)

  let transcript = common_scalar(i_1, transcript)
  let transcript = common_scalar(i_2, transcript)

  let (a1, transcript) = read_point(transcript)
  let (a2, transcript) = read_point(transcript)
  let (a3, transcript) = read_point(transcript)
  let (a4, transcript) = read_point(transcript)
  trace @"accumulated_before_theta_size": bytearray.length(
    transcript.accumulated_for_hash,
  )
  let (theta, transcript) = squeeze_challenge(transcript)
  trace @"theta": theta
  let (beta, transcript) = squeeze_challenge(transcript)
  trace @"beta": beta
  let (gamma, transcript) = squeeze_challenge(transcript)
  trace @"gamma": gamma
  let (permutations_committed_a, transcript) = read_point(transcript)
  let (permutations_committed_b, transcript) = read_point(transcript)
  let (permutations_committed_c, transcript) = read_point(transcript)
  let (permutations_committed_d, transcript) = read_point(transcript)
  let (permutations_committed_e, transcript) = read_point(transcript)
  let (permutations_committed_f, transcript) = read_point(transcript)
  // NOTE: halo2 transcript order is:
  //   1. Read random_poly_commitment (vanishing_rand) BEFORE y
  //   2. Squeeze y
  //   3. Read h_commitments (vanishing_split_1, vanishing_split_2) AFTER y
  // DEBUG: Original (WRONG) order was: vanishing_rand, y, vanishing_split_1/2
  // DEBUG: First fix (also WRONG) was: vanishing_split_1/2, y, vanishing_rand
  let (vanishing_rand, transcript) = read_point(transcript)
  trace @"before_y_squeeze accumulated size": bytearray.length(
    transcript.accumulated_for_hash,
  )
  let (y, transcript) = squeeze_challenge(transcript)
  trace @"y (for Horner)": y
  trace @"after_y_squeeze accumulated size": bytearray.length(
    transcript.accumulated_for_hash,
  )
  let (vanishing_split_1, transcript) = read_point(transcript)
  trace @"vanishing_split_1 (compressed)": vanishing_split_1
  let vanishing_split_1 = decompress(vanishing_split_1)
  let (vanishing_split_2, transcript) = read_point(transcript)
  trace @"vanishing_split_2 (compressed)": vanishing_split_2
  let vanishing_split_2 = decompress(vanishing_split_2)
  trace @"before_x_squeeze accumulated size": bytearray.length(
    transcript.accumulated_for_hash,
  )
  // Trace bytes at position 674-773 (data added after y squeeze)
  trace @"before_x bytes [674..773]": bytearray.drop(
    bytearray.take(transcript.accumulated_for_hash, 773),
    674,
  )
  let (x, transcript) = squeeze_challenge(transcript)
  trace @"x (evaluation point)": x
  let (advice_eval_1, transcript) = read_scalar(transcript)
  trace @"1rot[0] advice_eval_1": advice_eval_1
  let (advice_eval_2, transcript) = read_scalar(transcript)
  trace @"1rot[1] advice_eval_2": advice_eval_2
  let (advice_eval_3, transcript) = read_scalar(transcript)
  trace @"1rot[2] advice_eval_3": advice_eval_3
  let (advice_eval_4, transcript) = read_scalar(transcript)
  trace @"1rot[3] advice_eval_4": advice_eval_4
  let (fixed_eval_1, transcript) = read_scalar(transcript)
  trace @"1rot[4] fixed_eval_1": fixed_eval_1
  let (fixed_eval_2, transcript) = read_scalar(transcript)
  trace @"1rot[5] fixed_eval_2": fixed_eval_2
  let (fixed_eval_3, transcript) = read_scalar(transcript)
  trace @"1rot[6] fixed_eval_3": fixed_eval_3
  let (fixed_eval_4, transcript) = read_scalar(transcript)
  trace @"1rot[7] fixed_eval_4": fixed_eval_4
  let (random_eval, transcript) = read_scalar(transcript)
  trace @"1rot[8] random_eval": random_eval
  let (permutation_common_1, transcript) = read_scalar(transcript)
  trace @"1rot[9] permutation_common_1": permutation_common_1
  let (permutation_common_2, transcript) = read_scalar(transcript)
  trace @"1rot[10] permutation_common_2": permutation_common_2
  let (permutation_common_3, transcript) = read_scalar(transcript)
  trace @"1rot[11] permutation_common_3": permutation_common_3
  let (permutation_common_4, transcript) = read_scalar(transcript)
  trace @"1rot[12] permutation_common_4": permutation_common_4
  let (permutation_common_5, transcript) = read_scalar(transcript)
  trace @"1rot[13] permutation_common_5": permutation_common_5
  let (permutation_common_6, transcript) = read_scalar(transcript)
  trace @"1rot[14] permutation_common_6": permutation_common_6
  let (permutations_evaluated_a_1, transcript) = read_scalar(transcript)
  trace @"permutations_evaluated_a_1 (z_0)": permutations_evaluated_a_1
  let (permutations_evaluated_a_2, transcript) = read_scalar(transcript)
  let (permutations_evaluated_a_3, transcript) = read_scalar(transcript)
  let (permutations_evaluated_b_1, transcript) = read_scalar(transcript)
  let (permutations_evaluated_b_2, transcript) = read_scalar(transcript)
  let (permutations_evaluated_b_3, transcript) = read_scalar(transcript)
  let (permutations_evaluated_c_1, transcript) = read_scalar(transcript)
  let (permutations_evaluated_c_2, transcript) = read_scalar(transcript)
  let (permutations_evaluated_c_3, transcript) = read_scalar(transcript)
  let (permutations_evaluated_d_1, transcript) = read_scalar(transcript)
  let (permutations_evaluated_d_2, transcript) = read_scalar(transcript)
  let (permutations_evaluated_d_3, transcript) = read_scalar(transcript)
  let (permutations_evaluated_e_1, transcript) = read_scalar(transcript)
  let (permutations_evaluated_e_2, transcript) = read_scalar(transcript)
  let (permutations_evaluated_e_3, transcript) = read_scalar(transcript)
  let (permutations_evaluated_f_1, transcript) = read_scalar(transcript)
  let (permutations_evaluated_f_2, transcript) = read_scalar(transcript)
  let (x1, transcript) = squeeze_challenge(transcript)
  let (x2, transcript) = squeeze_challenge(transcript)
  let (f_commitment, transcript) = read_point(transcript)
  let (x3, transcript) = squeeze_challenge(transcript)
  trace @"x3": x3
  let (q_eval_on_x3_1, transcript) = read_scalar(transcript)
  trace @"q_eval_on_x3_1": q_eval_on_x3_1
  let (q_eval_on_x3_2, transcript) = read_scalar(transcript)
  trace @"q_eval_on_x3_2": q_eval_on_x3_2
  let (q_eval_on_x3_3, transcript) = read_scalar(transcript)
  trace @"q_eval_on_x3_3": q_eval_on_x3_3
  let (x4, transcript) = squeeze_challenge(transcript)
  trace @"x4": x4
  let (pi_term, _) = read_point(transcript)
  trace @"pi_term": pi_term

  // VPNPaymentCircuit uses k=8, so n=2^8=256 rows
  let n = 256
  let xn = scale(x, n)
  trace @"x": x
  trace @"xn (x^256)": xn

  let x_prev = rotate_omega(omega, omega_inv, x, -1)
  let x_current = rotate_omega(omega, omega_inv, x, 0)
  let x_next = rotate_omega(omega, omega_inv, x, 1)
  let x_last = rotate_omega(omega, omega_inv, x, -(blinding_factors + 1))

  // Debug: trace point values for f_eval computation
  trace @"x (evaluation point)": x
  trace @"x_current (omega^0 * x)": x_current
  trace @"x_next (omega^1 * x)": x_next
  trace @"x_last (omega^-6 * x)": x_last

  let evaluations_of_lagrange_polynomial =
    lagrange_polynomial_basis(
      x,
      xn,
      barycentric_weight,
      rotations_for_vanishing,
    )
  expect [last_evaluation, ..rest] = evaluations_of_lagrange_polynomial
  let evaluation_for_blinding_factors = take(rest, blinding_factors)
  expect Some(evaluation_at_0) = last(rest)
  let sum_of_evaluation_for_blinding_factors =
    foldl(
      evaluation_for_blinding_factors,
      scalarZero,
      fn(e, acc) { add(e, acc) },
    )
  let active_rows =
    sub(scalarOne, add(last_evaluation, sum_of_evaluation_for_blinding_factors))
  trace @"evaluation_at_0 (l_0)": evaluation_at_0
  trace @"last_evaluation (l_last)": last_evaluation
  trace @"sum_of_evaluation_for_blinding_factors (l_blind)": sum_of_evaluation_for_blinding_factors

  // -----------------------------------------------------------------------------------------------
  let rotations_for_instances = rotate_omegas(omega, omega_inv, 0, 2)
  let lagrange_polynomial_instances =
    lagrange_polynomial_basis(
      x,
      xn,
      barycentric_weight,
      rotations_for_instances,
    )
  let instance_eval_1 = inner_product(lagrange_polynomial_instances, [i_1, i_2])

  let gate_eq1 = mul(fixed_eval_2, add(advice_eval_1, neg(advice_eval_1)))
  let gate_eq2 =
    mul(
      fixed_eval_3,
      add(
        add(add(advice_eval_1, advice_eval_2), advice_eval_3),
        neg(advice_eval_4),
      ),
    )
  let gate_eq3 =
    mul(
      fixed_eval_4,
      add(add(advice_eval_1, neg(advice_eval_2)), neg(advice_eval_3)),
    )

  let term_1 =
    mul(evaluation_at_0, add(scalarOne, neg(permutations_evaluated_a_1)))
  let term_2 =
    mul(
      last_evaluation,
      add(
        mul(permutations_evaluated_f_1, permutations_evaluated_f_1),
        neg(permutations_evaluated_f_1),
      ),
    )
  let term_3 =
    mul(
      add(permutations_evaluated_b_1, neg(permutations_evaluated_a_3)),
      evaluation_at_0,
    )
  let term_4 =
    mul(
      add(permutations_evaluated_c_1, neg(permutations_evaluated_b_3)),
      evaluation_at_0,
    )
  let term_5 =
    mul(
      add(permutations_evaluated_d_1, neg(permutations_evaluated_c_3)),
      evaluation_at_0,
    )
  let term_6 =
    mul(
      add(permutations_evaluated_e_1, neg(permutations_evaluated_d_3)),
      evaluation_at_0,
    )
  let term_7 =
    mul(
      add(permutations_evaluated_f_1, neg(permutations_evaluated_e_3)),
      evaluation_at_0,
    )

  let left1 = add(add(instance_eval_1, mul(beta, permutation_common_1)), gamma)
  //part of set a
  let left2 = add(add(fixed_eval_1, mul(beta, permutation_common_2)), gamma)
  //part of set b
  let left3 = add(add(advice_eval_1, mul(beta, permutation_common_3)), gamma)
  //part of set c
  let left4 = add(add(advice_eval_2, mul(beta, permutation_common_4)), gamma)
  //part of set d
  let left5 = add(add(advice_eval_3, mul(beta, permutation_common_5)), gamma)
  //part of set e
  let left6 = add(add(advice_eval_4, mul(beta, permutation_common_6)), gamma)

  //part of set f
  let left_set1 = mul(permutations_evaluated_a_2, left1)
  let left_set2 = mul(permutations_evaluated_b_2, left2)
  let left_set3 = mul(permutations_evaluated_c_2, left3)
  let left_set4 = mul(permutations_evaluated_d_2, left4)
  let left_set5 = mul(permutations_evaluated_e_2, left5)
  let left_set6 = mul(permutations_evaluated_f_2, left6)

  let right1 =
    add(add(instance_eval_1, mul(mul(beta, x), scale(scalarDelta, 0))), gamma)
  //part of set a
  let right2 =
    add(add(fixed_eval_1, mul(mul(beta, x), scale(scalarDelta, 1))), gamma)
  //part of set b
  let right3 =
    add(add(advice_eval_1, mul(mul(beta, x), scale(scalarDelta, 2))), gamma)
  //part of set c
  let right4 =
    add(add(advice_eval_2, mul(mul(beta, x), scale(scalarDelta, 3))), gamma)
  //part of set d
  let right5 =
    add(add(advice_eval_3, mul(mul(beta, x), scale(scalarDelta, 4))), gamma)
  //part of set e
  let right6 =
    add(add(advice_eval_4, mul(mul(beta, x), scale(scalarDelta, 5))), gamma)

  //part of set f
  let right_set1 = mul(permutations_evaluated_a_1, right1)
  let right_set2 = mul(permutations_evaluated_b_1, right2)
  let right_set3 = mul(permutations_evaluated_c_1, right3)
  let right_set4 = mul(permutations_evaluated_d_1, right4)
  let right_set5 = mul(permutations_evaluated_e_1, right5)
  let right_set6 = mul(permutations_evaluated_f_1, right6)

  let permutations1 =
    mul(
      sub(left_set1, right_set1),
      sub(
        scalarOne,
        add(last_evaluation, sum_of_evaluation_for_blinding_factors),
      ),
    )
  let permutations2 =
    mul(
      sub(left_set2, right_set2),
      sub(
        scalarOne,
        add(last_evaluation, sum_of_evaluation_for_blinding_factors),
      ),
    )
  let permutations3 =
    mul(
      sub(left_set3, right_set3),
      sub(
        scalarOne,
        add(last_evaluation, sum_of_evaluation_for_blinding_factors),
      ),
    )
  let permutations4 =
    mul(
      sub(left_set4, right_set4),
      sub(
        scalarOne,
        add(last_evaluation, sum_of_evaluation_for_blinding_factors),
      ),
    )
  let permutations5 =
    mul(
      sub(left_set5, right_set5),
      sub(
        scalarOne,
        add(last_evaluation, sum_of_evaluation_for_blinding_factors),
      ),
    )
  let permutations6 =
    mul(
      sub(left_set6, right_set6),
      sub(
        scalarOne,
        add(last_evaluation, sum_of_evaluation_for_blinding_factors),
      ),
    )

  //      expressions for vanishing polynomial
  let expression1 = gate_eq1
  let expression2 = gate_eq2
  let expression3 = gate_eq3
  let expression4 = term_1
  let expression5 = term_2
  let expression6 = term_3
  let expression7 = term_4
  let expression8 = term_5
  let expression9 = term_6
  let expression10 = term_7
  let expression11 = permutations1
  let expression12 = permutations2
  let expression13 = permutations3
  let expression14 = permutations4
  let expression15 = permutations5
  let expression16 = permutations6
  trace @"expr[0]": expression1
  trace @"expr[1]": expression2
  trace @"expr[2]": expression3
  trace @"expr[3]": expression4
  trace @"expr[4]": expression5
  trace @"expr[5]": expression6
  trace @"expr[6]": expression7
  trace @"expr[7]": expression8
  trace @"expr[8]": expression9
  trace @"expr[9]": expression10
  trace @"expr[10]": expression11
  trace @"expr[11]": expression12
  trace @"expr[12]": expression13
  trace @"expr[13]": expression14
  trace @"expr[14]": expression15
  trace @"expr[15]": expression16

  let hEval =
    add(
      mul(
        add(
          mul(
            add(
              mul(
                add(
                  mul(
                    add(
                      mul(
                        add(
                          mul(
                            add(
                              mul(
                                add(
                                  mul(
                                    add(
                                      mul(
                                        add(
                                          mul(
                                            add(
                                              mul(
                                                add(
                                                  mul(
                                                    add(
                                                      mul(
                                                        add(
                                                          mul(
                                                            add(
                                                              mul(
                                                                add(
                                                                  mul(
                                                                    scalarZero,
                                                                    y,
                                                                  ),
                                                                  expression1,
                                                                ),
                                                                y,
                                                              ),
                                                              expression2,
                                                            ),
                                                            y,
                                                          ),
                                                          expression3,
                                                        ),
                                                        y,
                                                      ),
                                                      expression4,
                                                    ),
                                                    y,
                                                  ),
                                                  expression5,
                                                ),
                                                y,
                                              ),
                                              expression6,
                                            ),
                                            y,
                                          ),
                                          expression7,
                                        ),
                                        y,
                                      ),
                                      expression8,
                                    ),
                                    y,
                                  ),
                                  expression9,
                                ),
                                y,
                              ),
                              expression10,
                            ),
                            y,
                          ),
                          expression11,
                        ),
                        y,
                      ),
                      expression12,
                    ),
                    y,
                  ),
                  expression13,
                ),
                y,
              ),
              expression14,
            ),
            y,
          ),
          expression15,
        ),
        y,
      ),
      expression16,
    )

  trace @"hEval (constraint polynomial at x)": hEval
  let xn_minus_1 = sub(xn, scalarOne)
  trace @"xn - 1": xn_minus_1
  let inverted = recip_eea(xn_minus_1)
  trace @"1/(xn - 1)": inverted
  // recip is inverse of the number mod bls12_381_field_prime
  let vanishing_s = mul(hEval, inverted)
  trace @"1rot[14] vanishing_s (computed)": vanishing_s

  // vanishing split IS PASSED IN REVERSE ORDER!!!
  // this is MSM done for h-commitments
  let hCommitment1 = addG1(scaleG1(zero, xn), vanishing_split_2)
  let vanishing_g = addG1(scaleG1(hCommitment1, xn), vanishing_split_1)

  let vanishing_g = compress(vanishing_g)

  // need to compress computed vanishing_g, because commitment_data expects compressed points
  //
  // IMPORTANT: halo2 orders commitment sets by BTreeMap insertion order of point_index_sets.
  // The actual order from halo2 debug output is: [1-rot, 3-rot, 2-rot]
  // NOT the intuitive [1-rot, 2-rot, 3-rot]!
  //
  // DEBUG: Old (incorrect) ordering was [1-rot, 2-rot, 3-rot]:
  // Rust's construct_intermediate_sets returns point_sets in order [1-rot, 3-rot, 2-rot]
  // This is based on how verifier queries are processed, not BTreeSet natural ordering.
  // commitment_data, point_sets, and proofX3QEvals must all use this same order.
  //
  // Order: [1-rot, 3-rot, 2-rot]
  let commitment_data =
    [
      // 1-rotation commitments (16 items, each with 1 evaluation at x_current)
      [
        (a1, [advice_eval_1]), (a2, [advice_eval_2]), (a3, [advice_eval_3]),
        (a4, [advice_eval_4]), (f1_commitment, [fixed_eval_1]),
        (f2_commitment, [fixed_eval_2]), (f3_commitment, [fixed_eval_3]),
        (f4_commitment, [fixed_eval_4]), (p1_commitment, [permutation_common_1]),
        (p2_commitment, [permutation_common_2]),
        (p3_commitment, [permutation_common_3]),
        (p4_commitment, [permutation_common_4]),
        (p5_commitment, [permutation_common_5]),
        (p6_commitment, [permutation_common_6]), (vanishing_g, [vanishing_s]),
        (vanishing_rand, [random_eval]),
      ],
      // 3-rotation commitments (5 items, each with 3 evaluations at x_current, x_next, x_last)
      [
        (
          permutations_committed_a,
          [
            permutations_evaluated_a_1, permutations_evaluated_a_2,
            permutations_evaluated_a_3,
          ],
        ),
        (
          permutations_committed_b,
          [
            permutations_evaluated_b_1, permutations_evaluated_b_2,
            permutations_evaluated_b_3,
          ],
        ),
        (
          permutations_committed_c,
          [
            permutations_evaluated_c_1, permutations_evaluated_c_2,
            permutations_evaluated_c_3,
          ],
        ),
        (
          permutations_committed_d,
          [
            permutations_evaluated_d_1, permutations_evaluated_d_2,
            permutations_evaluated_d_3,
          ],
        ),
        (
          permutations_committed_e,
          [
            permutations_evaluated_e_1, permutations_evaluated_e_2,
            permutations_evaluated_e_3,
          ],
        ),
      ],
      // 2-rotation commitments (1 item with 2 evaluations at x_current, x_next)
      [
        (
          permutations_committed_f,
          [permutations_evaluated_f_1, permutations_evaluated_f_2],
        ),
      ],
    ]

  // Point sets must match Rust's construct_intermediate_sets order: [1-rot, 3-rot, 2-rot]
  trace @"Testing point_sets order"
  let point_sets =
    [[x_current], [x_current, x_next, x_last], [x_current, x_next]]

  // left and s_g2
  // right and g2
  // g2 is not negated as final_exponentiation is doing negation
  let g2 = generatorG2

  let x1Powers = powers(16, x1)
  let x4Powers = powers(4, x4)

  expect Some(x1p0) = list.head(x1Powers)
  expect [_, x1p1, ..] = x1Powers
  trace @"x1Powers[0] (should be 1)": x1p0
  trace @"x1Powers[1] (should be x1)": x1p1
  trace @"x1 (for reference)": x1
  trace @"x1Powers full list": x1Powers
  trace @"starting MSM"
  // proofX3QEvals are written by prover in construct_intermediate_sets order: [1-rot, 3-rot, 2-rot]
  // q_eval_on_x3_1 is for 1-rot, q_eval_on_x3_2 is for 3-rot, q_eval_on_x3_3 is for 2-rot
  let er =
    compute_msm(
      x1Powers,
      x2,
      x3,
      x4Powers,
      f_commitment,
      pi_term,
      [q_eval_on_x3_1, q_eval_on_x3_2, q_eval_on_x3_3],
      commitment_data,
      point_sets,
    )

  trace @"MSM computed, decompressing pi_term"
  let el = decompress(pi_term)
  trace @"el (pi_term)": compress(el)
  trace @"er (msm result)": compress(er)
  trace @"pi_term decompressed, starting pairing"

  // Test: if final_verify checks ml_a == ml_b (equality not product)
  // Then we need: e(pi, sG2) == e(msm, G2) directly
  // NO negation needed
  trace @"Testing: e(pi, sG2) == e(msm, G2) without negation"
  // Debug: trace G2 points to compare with Rust
  trace @"g2_const (s*G2)": compress_g2(g2_const)
  trace @"g2 (generator)": compress_g2(g2)

  // Try different pairing formulations
  // Formulation 1: e(pi, s*G2) == e(msm, G2)
  let ml_l = miller_loop(el, g2_const)
  let ml_r = miller_loop(er, g2)
  trace @"Formulation 1 - e(pi, s*G2) == e(msm, G2)"
  let result1 = final_exponentiation(ml_l, ml_r)
  trace @"result1": result1

  // Formulation 2: e(msm, s*G2) == e(pi, G2) (swap el and er)
  let ml_l2 = miller_loop(er, g2_const)
  let ml_r2 = miller_loop(el, g2)
  trace @"Formulation 2 - e(msm, s*G2) == e(pi, G2)"
  let result2 = final_exponentiation(ml_l2, ml_r2)
  trace @"result2": result2

  // Formulation 3: Use negated er
  let neg_er = subG1(zero, er)
  let ml_l3 = miller_loop(el, g2_const)
  let ml_r3 = miller_loop(neg_er, g2)
  trace @"Formulation 3 - e(pi, s*G2) == e(-msm, G2)"
  let result3 = final_exponentiation(ml_l3, ml_r3)
  trace @"result3": result3

  // For now return result1 but trace all results for debugging
  result1
}

// VPNPaymentCircuit proof test with real BLS12-381 proof data
// Proof generated from IOG halo2 fork with k=8, n=256, AikenHashState transcript
// Public inputs: pricing_tier=0, nullifier=0x0807060504030202
test check_valid_proof_valid_public_inputs() {
  expect
    verifier(
      #"88ced9f6d7f9efc1f32469f2dba53bc0b7a7a2f5315c200c294ddd3269c33b01357f63a93bc8ef004041b430247bacba836448ee172e2743ee6a919d7157a0b2cf14ced25b7330b8c38ba8e25465d3d702b60fbfc5ba4403c3cfdbe428324a66a0f33e3a2670b5551e66053decab2081fd9a054642ce79cced3e8042da5a90046620fa66a2c241058144e6383e701339a370ab3bf7cc161c85d237b5e44a51863ea85049515610fda4d55a607034e7a0fe609c179135ddc8d5ecb38fbe6795cb892d6f49b24e798e81b7082f8ce2c30e5bf52620e4b3d56caa091e676e2a71e19d1ccc46b6c1ae8ac0e2a88d8e20471a822b668518f602afe3bad1327d10a6741a0d27a81e730bbc0ac5070469bc5155429135f985401d375ab328cb947e7bbfa1b2882bf962b37a51ba65ec7b52f5c9426f3576c247ca816e72fea7cec58e2c5dd33e65e8d4b9d3bd69636011802b4eb911afc35c6fb2bfe171d553975f734d779ddb9b9f500bb570462c5e8c5f6377dfde2b959dcf251197804ad038e41cd8a27439cb9eb023d73219d747e3a4d2d04aa9b64d844076e32ffbf99eba3426d88549ac4e27bce287987bc6619c27d118b22fd25e18c23d380619a2d734836828b33cfec92701622af3302fd9df669119c8631c02314282545595de25f6f5fbefb963373adca67078f0d356007103f915408dba2e6cfd361e6ec73df758b50d7280f8f57131773746ee9e848e373090169189b5a3ae33daecc655ecdcc156888bfebeaff702ffbbf8f9cda1477d3fca5a8ec61c6ad1f2b736646c6f695e7c336c8b477d72d08db8c980109619471ef8479e9e1070be5a0fe6bafd505432f4db326c6e66e44cc04e7e85489d0545766ba77a1895489a1d0af6248b021bbfedf3ef4b2267240fe353f324eaff1c2059f82f3384a6412624795cbb8c6f6698e17511a9d99e2b20a65749a11f47616ccf1e5f969d44b391b2e4659a04da0ecf3dca222cbf77f71b0d43e586b9012152f01e4f8ea2be35095bdd72c6fd2d9dec66fd0fd4c39614101f68195d78729f30a70b61000000000000000000000000000000000000000000000000000000000000000056b4e0315acb18476b7975c4c7bd59db130d76551e94d1f2210d36675c17c65fd819b19962bdd26e09966c543145c4fbed41bd1b90ae704ac9d09914df7ba84dcc90356c7e68526db680be763c2a9bede78503c99f76a3d239fbc71e610a09066a7023e0f87add47c35be9e8210494cc283e247777f14b91796d52601369904c049505f809e60b4f5704505dd3594f1059fc19b9b3448f6153101e3a2b7c0a36b2ab81c8d973d925e3bb98c986edbd64f7d11767425469f711159d5ca16f9564310debb55afa8bf541d2805ddaf74b65791dbb7dd61d6b926d4e3f7289958c1f0c058d6ba596801e189ba83531025cbcc81f5392727a13ce93fd4a1467e38808658643dba1311c61836f33e2756d640e6b274ecdc1103b7f3d484d526e96f2189cca6e46acf01982d9aade3844805cdbbb02d922baeba0f2ec02cf6b3d4111099a77c57835b73a5d9ee8aa66683a708a96c4657b710d78f3a2253674c4b0a7391ae054c5f2b01434af1831d6838c9ddd1a990c21129c51ef605972f546426470f8e1552ba83864a238e3b04c58de49072b4558368c9fa0d9c7243128b617053366a04f341e1b8aec6e04b8ee5c5f47c887a040793a2680cbbef3ada5d7efc125f95fef046f13ebcfbe7687f9d612c54fae283b3870e2835a82c7e24a9ba2f71f979657faa96ebe64ea8718d01020c13406b2cd292de95a588af170ff055fab3bbb71d2af5376eed748b59f4bd4d87a664ee69eee55582537ff2e2ef4494eac22a116e8678f79ee2c548bfcf3fc1bc561e5f23604a748da381cdb4580f353f46c4a01f8563cab96b2f6e65e59f6d7a7d4ba76e89ed543027edd3dc05355c68d556bb83b823c6188519b04813d311f461713f69d58f8f1d809c92e3f885ebe424a098c918e5874587dca5653ea66831850f3a5fa3e65a2ebf263cc1c2852fe5f46a89559792d45b7ccf7eb2415a7215ea068475d84ea32ca3a360028f64609e42e95841fc157a344562351faa945ab436a460e11e5ec4bdf7a93b3d896e9c2643812809519c314183773a27cc36add4f56b8ad39b2436568e3e827e65333dfa1127f0a6f49ea8414f17258529f30df203bad9d7496511cc64033640fc21f203a12369bc563702d860e998cac36ad009e5a59d9fddace867808800c2acb88b64a59eb10dd1dca7a00e5a8265bcffdcf6f997304e8d7dd15beccdd3ba36b9c97c92492070d8751527cfe09f4dc1217442d9587ea79ad30ca0d26e1a1669d64ab122cc8d5b7a215a65256855ca81768c5bd904ff390fb9403b2eea66a97a6b35f01cd95507e0dd249ad6abbfbb24ffa4d094603fde3a5f63a43cebe1e0fee7c568fa8b8c3e9958ae357f4d99ec573f739403d1eb3c212c2597f535888300f92169d79d3c4ee13eee785b024bb4b275e2f4503b55e33f78a3ac8437db33e32c26ccee1fa98588064778f659af9a245be80c99610b67d008e004dc603175444d5b949e9",
      from_int(0),
      from_int(0x807060504030202),
    ) == True
}

// Test with valid proof but wrong public inputs - should return False
test check_proof_invalid_public_inputs() {
  // Using the same valid proof but with wrong pricing_tier (1 instead of 0) and wrong nullifier (0xdeadbeef instead of 0x0807060504030202)
  expect
    verifier(
      #"88ced9f6d7f9efc1f32469f2dba53bc0b7a7a2f5315c200c294ddd3269c33b01357f63a93bc8ef004041b430247bacba836448ee172e2743ee6a919d7157a0b2cf14ced25b7330b8c38ba8e25465d3d702b60fbfc5ba4403c3cfdbe428324a66a0f33e3a2670b5551e66053decab2081fd9a054642ce79cced3e8042da5a90046620fa66a2c241058144e6383e701339a370ab3bf7cc161c85d237b5e44a51863ea85049515610fda4d55a607034e7a0fe609c179135ddc8d5ecb38fbe6795cb892d6f49b24e798e81b7082f8ce2c30e5bf52620e4b3d56caa091e676e2a71e19d1ccc46b6c1ae8ac0e2a88d8e20471a822b668518f602afe3bad1327d10a6741a0d27a81e730bbc0ac5070469bc5155429135f985401d375ab328cb947e7bbfa1b2882bf962b37a51ba65ec7b52f5c9426f3576c247ca816e72fea7cec58e2c5dd33e65e8d4b9d3bd69636011802b4eb911afc35c6fb2bfe171d553975f734d779ddb9b9f500bb570462c5e8c5f6377dfde2b959dcf251197804ad038e41cd8a27439cb9eb023d73219d747e3a4d2d04aa9b64d844076e32ffbf99eba3426d88549ac4e27bce287987bc6619c27d118b22fd25e18c23d380619a2d734836828b33cfec92701622af3302fd9df669119c8631c02314282545595de25f6f5fbefb963373adca67078f0d356007103f915408dba2e6cfd361e6ec73df758b50d7280f8f57131773746ee9e848e373090169189b5a3ae33daecc655ecdcc156888bfebeaff702ffbbf8f9cda1477d3fca5a8ec61c6ad1f2b736646c6f695e7c336c8b477d72d08db8c980109619471ef8479e9e1070be5a0fe6bafd505432f4db326c6e66e44cc04e7e85489d0545766ba77a1895489a1d0af6248b021bbfedf3ef4b2267240fe353f324eaff1c2059f82f3384a6412624795cbb8c6f6698e17511a9d99e2b20a65749a11f47616ccf1e5f969d44b391b2e4659a04da0ecf3dca222cbf77f71b0d43e586b9012152f01e4f8ea2be35095bdd72c6fd2d9dec66fd0fd4c39614101f68195d78729f30a70b61000000000000000000000000000000000000000000000000000000000000000056b4e0315acb18476b7975c4c7bd59db130d76551e94d1f2210d36675c17c65fd819b19962bdd26e09966c543145c4fbed41bd1b90ae704ac9d09914df7ba84dcc90356c7e68526db680be763c2a9bede78503c99f76a3d239fbc71e610a09066a7023e0f87add47c35be9e8210494cc283e247777f14b91796d52601369904c049505f809e60b4f5704505dd3594f1059fc19b9b3448f6153101e3a2b7c0a36b2ab81c8d973d925e3bb98c986edbd64f7d11767425469f711159d5ca16f9564310debb55afa8bf541d2805ddaf74b65791dbb7dd61d6b926d4e3f7289958c1f0c058d6ba596801e189ba83531025cbcc81f5392727a13ce93fd4a1467e38808658643dba1311c61836f33e2756d640e6b274ecdc1103b7f3d484d526e96f2189cca6e46acf01982d9aade3844805cdbbb02d922baeba0f2ec02cf6b3d4111099a77c57835b73a5d9ee8aa66683a708a96c4657b710d78f3a2253674c4b0a7391ae054c5f2b01434af1831d6838c9ddd1a990c21129c51ef605972f546426470f8e1552ba83864a238e3b04c58de49072b4558368c9fa0d9c7243128b617053366a04f341e1b8aec6e04b8ee5c5f47c887a040793a2680cbbef3ada5d7efc125f95fef046f13ebcfbe7687f9d612c54fae283b3870e2835a82c7e24a9ba2f71f979657faa96ebe64ea8718d01020c13406b2cd292de95a588af170ff055fab3bbb71d2af5376eed748b59f4bd4d87a664ee69eee55582537ff2e2ef4494eac22a116e8678f79ee2c548bfcf3fc1bc561e5f23604a748da381cdb4580f353f46c4a01f8563cab96b2f6e65e59f6d7a7d4ba76e89ed543027edd3dc05355c68d556bb83b823c6188519b04813d311f461713f69d58f8f1d809c92e3f885ebe424a098c918e5874587dca5653ea66831850f3a5fa3e65a2ebf263cc1c2852fe5f46a89559792d45b7ccf7eb2415a7215ea068475d84ea32ca3a360028f64609e42e95841fc157a344562351faa945ab436a460e11e5ec4bdf7a93b3d896e9c2643812809519c314183773a27cc36add4f56b8ad39b2436568e3e827e65333dfa1127f0a6f49ea8414f17258529f30df203bad9d7496511cc64033640fc21f203a12369bc563702d860e998cac36ad009e5a59d9fddace867808800c2acb88b64a59eb10dd1dca7a00e5a8265bcffdcf6f997304e8d7dd15beccdd3ba36b9c97c92492070d8751527cfe09f4dc1217442d9587ea79ad30ca0d26e1a1669d64ab122cc8d5b7a215a65256855ca81768c5bd904ff390fb9403b2eea66a97a6b35f01cd95507e0dd249ad6abbfbb24ffa4d094603fde3a5f63a43cebe1e0fee7c568fa8b8c3e9958ae357f4d99ec573f739403d1eb3c212c2597f535888300f92169d79d3c4ee13eee785b024bb4b275e2f4503b55e33f78a3ac8437db33e32c26ccee1fa98588064778f659af9a245be80c99610b67d008e004dc603175444d5b949e9",
      from_int(1),
      from_int(0xdeadbeef),
    ) == False
}
