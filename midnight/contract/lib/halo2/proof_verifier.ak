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
  // IMPORTANT: halo2 orders commitment sets by BTreeSet comparison of rotation indices.
  // BTreeSet<usize> ordering: {0} < {0,1} < {0,1,2} (lexicographic on sorted sets)
  // This gives the order: [1-point, 2-point, 3-point]
  //
  // commitment_data, point_sets, and proofX3QEvals must all use this same order.
  //
  // Order: [1-rot, 2-rot, 3-rot]
  let commitment_data =
    [
      // Index 0: 1-rotation commitments (16 items, each with 1 evaluation at x_current)
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
      // Index 1: 2-rotation commitments (1 item with 2 evaluations at x_current, x_next)
      [
        (
          permutations_committed_f,
          [permutations_evaluated_f_1, permutations_evaluated_f_2],
        ),
      ],
      // Index 2: 3-rotation commitments (5 items, each with 3 evaluations at x_current, x_next, x_last)
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
    ]

  // Point sets must match halo2's BTreeSet ordering: [1-rot, 2-rot, 3-rot]
  trace @"Testing point_sets order"
  let point_sets =
    [[x_current], [x_current, x_next], [x_current, x_next, x_last]]

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
// Proof generated from simplified circuit (nullifier as public input from Midnight)
// Public inputs: pricing_tier=1, nullifier from Midnight persistentHash
test check_valid_proof_valid_public_inputs() {
  expect
    verifier(
      #"aaca2de5d319fcedc4a92ca4c7d5972d805352259214956f4fc5b10670f79d9c83cf271da48b44050074f635f96e1f698c1502377b3002c73fd026dd12c540c4fa9ec4ce17bb0737cd16e56c52d98df35e77c07530e9b47e23a22ee6ee8160a38e15e5b6b3a9bdd4a1e3412cd32d589bbd167fdd8830a2d148fa75affb1a2237e9a173d0ddc903ed30d2be556936b86a8820c115bfc7f3e2965fb87760a7a4c8bb35ec4f7aaed8580e02b6e5a322595d06e8ec31feb994614b382cde2f2fad928288d8dc1c837b10e6f23782059158fe5594225d50093138a582abadda798bb7a26f53f3c04a940ecda63bdbb9620b66b3ae66b248c78025adad9516320347f6dcc549a39c04953bf8f5e92b5a002f1d6f2f9bbf9a06e6433066c6b38be02d3aae53813d3a0deef1d1b4aa9260e7156c720b9df2376d3e33d871e2a4b50d8b9d2c75d998849f29a12c4894b7a55e1aa2aaf4bf9c893c478e4aa34994d2506b0630b22056dad642498709058e3076bcac549e3800910085c8d697cba6178cb06da9fd445f9b439483a4f1e298a3b75dd8707aac7b9d48918aab0e1e20e9b47539ecb97fd918864d805005e64e08f54851a98c2741cae7719b80155fbad11510ac762d93b7cbec4548f21e1dc1b738bc191e95677d71ff800ce2485fa68dc38adead8cf6cfb5773546074344dc33cdab0580306af104a7a452279329716745998a472f330e9ad7a8a203be33de7c7076feb5fb22ade76d95cc59e315ae2f06ed2d3a4130f6b3da648472f8751ef4cfc7a44a3f4332d431fb1e59f6dad751476ed184880924d9e2c35c23b8390b2f6e8708461deb94a07fb24f83578e9c88b7ad6c38bbe81acd344682329fb16810ce7df1a18d69b6c47ad50754bb389ad42989ccfb5493d329ad466d110089412efca74a23583d5aba2388b36cb19b759d0ffdf744bb6c98dfe45eb63cb4e94fc34d821422b9740e54cac45cb9ef5165c5034fb015ee264edee2528c06c97cf32887ab1a0c9cd3be3ca3b62fd3e669fb206fc1bcc5e4bc9ac8f4a8905d8109bc5e36495d0000000000000000000000000000000000000000000000000000000000000000c88f364f3cf59440493ae0aa9578d580761192c90e9a3a163c8740a0d1baf93a00000000000000000000000000000000000000000000000000000000000000009422e5adec76b029d7dd6b52e43f23f76b3e241ec8ca37ede8f2e9557807cd22c6a88e8d74595d4582c1f4b20ce12000c35e06d44e53e58186d2250a012127289ddeff6957617b72e844a4d466a8c80788a5d49bf81f08d50ba839ba964b8c3cb4d32228f294618993007c59d09e6d0ca6b1d037e53614140a7a269db071b46ad36be6d947504e77fc0a0ac222021a7fa49c6f1bcf85484ecb49185a8a9146429535296ffa8cb8adbe8f58dcf852ba668d00e1b00dff325bb10134b763a8e120c74e64cbb76b895771c98ce0979b05c5cd934815bd3e2e9085eaa1290ae6931306f383c1be8d3c1b9c5be08280ecf261ed0b28186f4598540f03e5ce6eb74c44fc2834730aa59926bc735f447560b4e89142cd25b06658950a8ac32f7f98c1621f15b0d5e533611528c5dee1da6a4d4eca4e74d172641f48889605130c1c372a9a86faf5a7b1ab2618e4cda540ae75d1d999be6bdb94e3c1dcecb8de3995974b2e003ee2f7c229fbb85e6dceb191394ac5c86ac8be08ee25a9ab158da0410e4d9b390cd06c85666ff82a1408248ec2ace93b2f9cc65dc8d4c4f0f8930e2f242e4d84f9bf529e7be8d4b749c5badb0b7fa749fe3509c422ff9c4a7d6c00425649938e100e660d22ac8adf07e4c4727673e6314762517bc470455468b27aa86a1a5a44cc08a7293ebd3ed9c110d1e7655e36d95fb8e2f79044074eb40a8df0c4620adaa45d7b97850aa0d9dba18934b0a38a134649c653241fd095ba02a61210067575775bb255e31f5519dd21429238f1947fe7a7cda4cb70cd42e7761e8d6b292bd503e1806b600d777802ff3d5e75b5a90181b9f92d8b40f75da15db8991f16b9ac743e83df1c70dbf621fb97504f1cde4723ec60d13b4142b5781817e341671881ac9ccb72973ae78709c7201f7aea2b932c5ceda246d2dc7a715c3dbc1a4038a3fa36a1707d0d3d9a6ba88f1ff2a0e0fb961037bb0c1064fb16e80855c81c1220daba2c2fa68c9ae0c6499be29e8c337124324606d8c8b823701c0074fc5aa0501d88592777f14717adf33f48dbac3dc9a72a7f7a37212118d6529a61e5651d23e216f6f7a905c2808b8b75f68b7bd26bb01fd3a8bccf21b1abee5a491d38a0222668ebff2da9de4dbf1f801abadb02191206e8a7dbb7861c3fe9aab9ac2eb9a3c0b0ce68b3fbeaa61c1533d1dfcfeb71bd04f646aba2876fb3eb249eea069d9e21002a0531d579612f4440c73d5920d358e9fe30d7089b28527494e3023dc51591430ce1e5070e2c36b13257ef3a81bb731aa22bc9499c52f91d10c45cf8e97274fced9da396e03157f5023fc12b8b0746025aae54e18eb68917dcfafb9513a4f20dc01058c22e28b745f351c5498fb0340e2021b2c4fd6ba5a0cc9042c0",
      from_int(1),
      from_int(0x147b051673afc0a6618006daf6f07889d5c8597599cb45b34c21bcf0da0c5f),
    ) == True
}

// Test with valid proof but wrong public inputs - should return False
test check_proof_invalid_public_inputs() {
  // Using the same valid proof but with wrong nullifier (0xdeadbeef instead of correct value)
  expect
    verifier(
      #"aaca2de5d319fcedc4a92ca4c7d5972d805352259214956f4fc5b10670f79d9c83cf271da48b44050074f635f96e1f698c1502377b3002c73fd026dd12c540c4fa9ec4ce17bb0737cd16e56c52d98df35e77c07530e9b47e23a22ee6ee8160a38e15e5b6b3a9bdd4a1e3412cd32d589bbd167fdd8830a2d148fa75affb1a2237e9a173d0ddc903ed30d2be556936b86a8820c115bfc7f3e2965fb87760a7a4c8bb35ec4f7aaed8580e02b6e5a322595d06e8ec31feb994614b382cde2f2fad928288d8dc1c837b10e6f23782059158fe5594225d50093138a582abadda798bb7a26f53f3c04a940ecda63bdbb9620b66b3ae66b248c78025adad9516320347f6dcc549a39c04953bf8f5e92b5a002f1d6f2f9bbf9a06e6433066c6b38be02d3aae53813d3a0deef1d1b4aa9260e7156c720b9df2376d3e33d871e2a4b50d8b9d2c75d998849f29a12c4894b7a55e1aa2aaf4bf9c893c478e4aa34994d2506b0630b22056dad642498709058e3076bcac549e3800910085c8d697cba6178cb06da9fd445f9b439483a4f1e298a3b75dd8707aac7b9d48918aab0e1e20e9b47539ecb97fd918864d805005e64e08f54851a98c2741cae7719b80155fbad11510ac762d93b7cbec4548f21e1dc1b738bc191e95677d71ff800ce2485fa68dc38adead8cf6cfb5773546074344dc33cdab0580306af104a7a452279329716745998a472f330e9ad7a8a203be33de7c7076feb5fb22ade76d95cc59e315ae2f06ed2d3a4130f6b3da648472f8751ef4cfc7a44a3f4332d431fb1e59f6dad751476ed184880924d9e2c35c23b8390b2f6e8708461deb94a07fb24f83578e9c88b7ad6c38bbe81acd344682329fb16810ce7df1a18d69b6c47ad50754bb389ad42989ccfb5493d329ad466d110089412efca74a23583d5aba2388b36cb19b759d0ffdf744bb6c98dfe45eb63cb4e94fc34d821422b9740e54cac45cb9ef5165c5034fb015ee264edee2528c06c97cf32887ab1a0c9cd3be3ca3b62fd3e669fb206fc1bcc5e4bc9ac8f4a8905d8109bc5e36495d0000000000000000000000000000000000000000000000000000000000000000c88f364f3cf59440493ae0aa9578d580761192c90e9a3a163c8740a0d1baf93a00000000000000000000000000000000000000000000000000000000000000009422e5adec76b029d7dd6b52e43f23f76b3e241ec8ca37ede8f2e9557807cd22c6a88e8d74595d4582c1f4b20ce12000c35e06d44e53e58186d2250a012127289ddeff6957617b72e844a4d466a8c80788a5d49bf81f08d50ba839ba964b8c3cb4d32228f294618993007c59d09e6d0ca6b1d037e53614140a7a269db071b46ad36be6d947504e77fc0a0ac222021a7fa49c6f1bcf85484ecb49185a8a9146429535296ffa8cb8adbe8f58dcf852ba668d00e1b00dff325bb10134b763a8e120c74e64cbb76b895771c98ce0979b05c5cd934815bd3e2e9085eaa1290ae6931306f383c1be8d3c1b9c5be08280ecf261ed0b28186f4598540f03e5ce6eb74c44fc2834730aa59926bc735f447560b4e89142cd25b06658950a8ac32f7f98c1621f15b0d5e533611528c5dee1da6a4d4eca4e74d172641f48889605130c1c372a9a86faf5a7b1ab2618e4cda540ae75d1d999be6bdb94e3c1dcecb8de3995974b2e003ee2f7c229fbb85e6dceb191394ac5c86ac8be08ee25a9ab158da0410e4d9b390cd06c85666ff82a1408248ec2ace93b2f9cc65dc8d4c4f0f8930e2f242e4d84f9bf529e7be8d4b749c5badb0b7fa749fe3509c422ff9c4a7d6c00425649938e100e660d22ac8adf07e4c4727673e6314762517bc470455468b27aa86a1a5a44cc08a7293ebd3ed9c110d1e7655e36d95fb8e2f79044074eb40a8df0c4620adaa45d7b97850aa0d9dba18934b0a38a134649c653241fd095ba02a61210067575775bb255e31f5519dd21429238f1947fe7a7cda4cb70cd42e7761e8d6b292bd503e1806b600d777802ff3d5e75b5a90181b9f92d8b40f75da15db8991f16b9ac743e83df1c70dbf621fb97504f1cde4723ec60d13b4142b5781817e341671881ac9ccb72973ae78709c7201f7aea2b932c5ceda246d2dc7a715c3dbc1a4038a3fa36a1707d0d3d9a6ba88f1ff2a0e0fb961037bb0c1064fb16e80855c81c1220daba2c2fa68c9ae0c6499be29e8c337124324606d8c8b823701c0074fc5aa0501d88592777f14717adf33f48dbac3dc9a72a7f7a37212118d6529a61e5651d23e216f6f7a905c2808b8b75f68b7bd26bb01fd3a8bccf21b1abee5a491d38a0222668ebff2da9de4dbf1f801abadb02191206e8a7dbb7861c3fe9aab9ac2eb9a3c0b0ce68b3fbeaa61c1533d1dfcfeb71bd04f646aba2876fb3eb249eea069d9e21002a0531d579612f4440c73d5920d358e9fe30d7089b28527494e3023dc51591430ce1e5070e2c36b13257ef3a81bb731aa22bc9499c52f91d10c45cf8e97274fced9da396e03157f5023fc12b8b0746025aae54e18eb68917dcfafb9513a4f20dc01058c22e28b745f351c5498fb0340e2021b2c4fd6ba5a0cc9042c0",
      from_int(1),
      from_int(0xdeadbeef),
    ) == False
}
