use aiken/collection/list.{last, foldl, take}
use aiken/crypto/bitwise.{State}
use aiken/crypto/bls12_381/g1.{add as addG1, scale as scaleG1, zero, decompress, compress}
use aiken/crypto/bls12_381/g2.{generator as generatorG2}
use aiken/crypto/bls12_381/scalar.{
  Scalar, add, from_int, mul, neg, scale, sub,
}
use bls_utils.{inner_product, recip_eea}
use lagrange.{lagrange_polynomial_basis}
use omega_rotations.{rotate_omegas, rotate_omega, powers}
use transcript.{
  common_scalar, construct_transcript, read_point, read_scalar,
  squeeze_challenge,
}
use verifier_key.{barycentric_weight, blinding_factors, omega, omega_inv, g2_const, transcript_rep, f1_commitment, f2_commitment, f3_commitment, f4_commitment, p1_commitment, p2_commitment, p3_commitment, p4_commitment, p5_commitment, p6_commitment }
use halo2_kzg.{compute_msm}
use aiken/crypto/bls12_381/pairing.{miller_loop, final_exponentiation}

pub fn verifier(proof: Data, i_1: State<Scalar>, i_2: State<Scalar>) -> Bool {

    let rotations_for_vanishing =
        rotate_omegas(omega, omega_inv, -(blinding_factors + 1), 0)

    let scalarZero = from_int(0)
    let scalarOne = from_int(1)
    let scalarDelta = from_int(0x08634d0aa021aaf843cab354fabb0062f6502437c6a09c006c083479590189d7)

    let inputs_count = from_int(2)

    let transcript = construct_transcript(proof, transcript_rep)
    let transcript = common_scalar(inputs_count, transcript)

    let transcript = common_scalar(i_1, transcript)
    let transcript = common_scalar(i_2, transcript)


    let (a1, transcript) = read_point(transcript)
    let (a2, transcript) = read_point(transcript)
    let (a3, transcript) = read_point(transcript)
    let (a4, transcript) = read_point(transcript)
    let (theta, transcript) = squeeze_challenge(transcript)
    let (beta, transcript) = squeeze_challenge(transcript)
    let (gamma, transcript) = squeeze_challenge(transcript)
    let (permutations_committed_a, transcript) = read_point(transcript)
    let (permutations_committed_b, transcript) = read_point(transcript)
    let (permutations_committed_c, transcript) = read_point(transcript)
    let (permutations_committed_d, transcript) = read_point(transcript)
    let (permutations_committed_e, transcript) = read_point(transcript)
    let (permutations_committed_f, transcript) = read_point(transcript)
    let (vanishing_rand, transcript) = read_point(transcript)
    let (y, transcript) = squeeze_challenge(transcript)
	let (vanishing_split_1, transcript) =  read_point(transcript)
	let vanishing_split_1 = decompress(vanishing_split_1)
	let (vanishing_split_2, transcript) =  read_point(transcript)
	let vanishing_split_2 = decompress(vanishing_split_2)
    let (x, transcript) = squeeze_challenge(transcript)
    let (advice_eval_1, transcript) = read_scalar(transcript)
    let (advice_eval_2, transcript) = read_scalar(transcript)
    let (advice_eval_3, transcript) = read_scalar(transcript)
    let (advice_eval_4, transcript) = read_scalar(transcript)
    let (fixed_eval_1, transcript) = read_scalar(transcript)
    let (fixed_eval_2, transcript) = read_scalar(transcript)
    let (fixed_eval_3, transcript) = read_scalar(transcript)
    let (fixed_eval_4, transcript) = read_scalar(transcript)
    let (random_eval, transcript) = read_scalar(transcript)
    let (permutation_common_1, transcript) = read_scalar(transcript)
    let (permutation_common_2, transcript) = read_scalar(transcript)
    let (permutation_common_3, transcript) = read_scalar(transcript)
    let (permutation_common_4, transcript) = read_scalar(transcript)
    let (permutation_common_5, transcript) = read_scalar(transcript)
    let (permutation_common_6, transcript) = read_scalar(transcript)
    let (permutations_evaluated_a_1, transcript) = read_scalar(transcript)
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
    let (f_commitment, transcript) =  read_point(transcript)
    let (x3, transcript) = squeeze_challenge(transcript)
    let (q_eval_on_x3_1, transcript) = read_scalar(transcript)
    let (q_eval_on_x3_2, transcript) = read_scalar(transcript)
    let (q_eval_on_x3_3, transcript) = read_scalar(transcript)
    let (x4, transcript) = squeeze_challenge(transcript)
    let (pi_term, _) =  read_point(transcript)



    let n = 16
    let xn = scale( x, n)

    let x_prev = rotate_omega(omega, omega_inv, x, (-1))
    let x_current = rotate_omega(omega, omega_inv, x, 0)
    let x_next = rotate_omega(omega, omega_inv, x, 1)
    let x_last = rotate_omega(omega, omega_inv, x, (-(blinding_factors + 1)))

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
    // -----------------------------------------------------------------------------------------------

    let rotations_for_instances = rotate_omegas(omega, omega_inv, 0, 2)
    let lagrange_polynomial_instances = lagrange_polynomial_basis( x, xn, barycentric_weight, rotations_for_instances)
    let instance_eval_1 = inner_product(lagrange_polynomial_instances, [i_1, i_2])

    let gate_eq1 = mul(fixed_eval_2, add(advice_eval_1,  neg(advice_eval_1) ))
    let gate_eq2 = mul(fixed_eval_3, add(add(add(advice_eval_1, advice_eval_2), advice_eval_3),  neg(advice_eval_4) ))
    let gate_eq3 = mul(fixed_eval_4, add(add(advice_eval_1,  neg(advice_eval_2) ),  neg(advice_eval_3) ))








    let term_1 = mul( evaluation_at_0 , add( scalarOne , neg( permutations_evaluated_a_1 )))
    let term_2 = mul( last_evaluation , add(mul( permutations_evaluated_f_1 ,  permutations_evaluated_f_1 ), neg( permutations_evaluated_f_1 )))
    let term_3 = mul(add( permutations_evaluated_b_1 , neg( permutations_evaluated_a_3 )),  evaluation_at_0 )
    let term_4 = mul(add( permutations_evaluated_c_1 , neg( permutations_evaluated_b_3 )),  evaluation_at_0 )
    let term_5 = mul(add( permutations_evaluated_d_1 , neg( permutations_evaluated_c_3 )),  evaluation_at_0 )
    let term_6 = mul(add( permutations_evaluated_e_1 , neg( permutations_evaluated_d_3 )),  evaluation_at_0 )
    let term_7 = mul(add( permutations_evaluated_f_1 , neg( permutations_evaluated_e_3 )),  evaluation_at_0 )


    let left1 = add(add(instance_eval_1, mul( beta , permutation_common_1)),  gamma ) //part of set a
    let left2 = add(add(fixed_eval_1, mul( beta , permutation_common_2)),  gamma ) //part of set b
    let left3 = add(add(advice_eval_1, mul( beta , permutation_common_3)),  gamma ) //part of set c
    let left4 = add(add(advice_eval_2, mul( beta , permutation_common_4)),  gamma ) //part of set d
    let left5 = add(add(advice_eval_3, mul( beta , permutation_common_5)),  gamma ) //part of set e
    let left6 = add(add(advice_eval_4, mul( beta , permutation_common_6)),  gamma ) //part of set f


    let left_set1 = mul(permutations_evaluated_a_2, left1) 
    let left_set2 = mul(permutations_evaluated_b_2, left2) 
    let left_set3 = mul(permutations_evaluated_c_2, left3) 
    let left_set4 = mul(permutations_evaluated_d_2, left4) 
    let left_set5 = mul(permutations_evaluated_e_2, left5) 
    let left_set6 = mul(permutations_evaluated_f_2, left6) 


    let right1 = add(add(instance_eval_1, mul(mul( beta ,  x ), scale( scalarDelta , 0))),  gamma ) //part of set a
    let right2 = add(add(fixed_eval_1, mul(mul( beta ,  x ), scale( scalarDelta , 1))),  gamma ) //part of set b
    let right3 = add(add(advice_eval_1, mul(mul( beta ,  x ), scale( scalarDelta , 2))),  gamma ) //part of set c
    let right4 = add(add(advice_eval_2, mul(mul( beta ,  x ), scale( scalarDelta , 3))),  gamma ) //part of set d
    let right5 = add(add(advice_eval_3, mul(mul( beta ,  x ), scale( scalarDelta , 4))),  gamma ) //part of set e
    let right6 = add(add(advice_eval_4, mul(mul( beta ,  x ), scale( scalarDelta , 5))),  gamma ) //part of set f


    let right_set1 = mul(permutations_evaluated_a_1, right1) 
    let right_set2 = mul(permutations_evaluated_b_1, right2) 
    let right_set3 = mul(permutations_evaluated_c_1, right3) 
    let right_set4 = mul(permutations_evaluated_d_1, right4) 
    let right_set5 = mul(permutations_evaluated_e_1, right5) 
    let right_set6 = mul(permutations_evaluated_f_1, right6) 


    let permutations1 = mul(sub(left_set1, right_set1), sub(scalarOne, add(last_evaluation, sum_of_evaluation_for_blinding_factors)))
    let permutations2 = mul(sub(left_set2, right_set2), sub(scalarOne, add(last_evaluation, sum_of_evaluation_for_blinding_factors)))
    let permutations3 = mul(sub(left_set3, right_set3), sub(scalarOne, add(last_evaluation, sum_of_evaluation_for_blinding_factors)))
    let permutations4 = mul(sub(left_set4, right_set4), sub(scalarOne, add(last_evaluation, sum_of_evaluation_for_blinding_factors)))
    let permutations5 = mul(sub(left_set5, right_set5), sub(scalarOne, add(last_evaluation, sum_of_evaluation_for_blinding_factors)))
    let permutations6 = mul(sub(left_set6, right_set6), sub(scalarOne, add(last_evaluation, sum_of_evaluation_for_blinding_factors)))


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


    let hEval = add(mul(add(mul(add(mul(add(mul(add(mul(add(mul(add(mul(add(mul(add(mul(add(mul(add(mul(add(mul(add(mul(add(mul(add(mul(add(mul(scalarZero, y), expression1), y), expression2), y), expression3), y), expression4), y), expression5), y), expression6), y), expression7), y), expression8), y), expression9), y), expression10), y), expression11), y), expression12), y), expression13), y), expression14), y), expression15), y), expression16)


    let inverted = recip_eea(sub(xn, scalarOne)) // recip is inverse of the number mod bls12_381_field_prime
    let vanishing_s = mul(hEval, inverted)

    // vanishing split IS PASSED IN REVERSE ORDER!!!
    // this is MSM done for h-commitments
    let hCommitment1 = addG1(scaleG1( zero ,  xn ),  vanishing_split_2 )
    let vanishing_g = addG1(scaleG1( hCommitment1 ,  xn ),  vanishing_split_1 )

    let vanishing_g = compress(vanishing_g) // need to compress computed vanishing_g, because commitment_data expects compressed points

	let commitment_data = [
		[
			(a1, [advice_eval_1]),
			(a2, [advice_eval_2]),
			(a3, [advice_eval_3]),
			(a4, [advice_eval_4]),
			(f1_commitment, [fixed_eval_1]),
			(f2_commitment, [fixed_eval_2]),
			(f3_commitment, [fixed_eval_3]),
			(f4_commitment, [fixed_eval_4]),
			(p1_commitment, [permutation_common_1]),
			(p2_commitment, [permutation_common_2]),
			(p3_commitment, [permutation_common_3]),
			(p4_commitment, [permutation_common_4]),
			(p5_commitment, [permutation_common_5]),
			(p6_commitment, [permutation_common_6]),
			(vanishing_g, [vanishing_s]),
			(vanishing_rand, [random_eval])
		],
		[
			(permutations_committed_a, [permutations_evaluated_a_1,permutations_evaluated_a_2,permutations_evaluated_a_3]),
			(permutations_committed_b, [permutations_evaluated_b_1,permutations_evaluated_b_2,permutations_evaluated_b_3]),
			(permutations_committed_c, [permutations_evaluated_c_1,permutations_evaluated_c_2,permutations_evaluated_c_3]),
			(permutations_committed_d, [permutations_evaluated_d_1,permutations_evaluated_d_2,permutations_evaluated_d_3]),
			(permutations_committed_e, [permutations_evaluated_e_1,permutations_evaluated_e_2,permutations_evaluated_e_3])
		],
		[
			(permutations_committed_f, [permutations_evaluated_f_1,permutations_evaluated_f_2])
		]]

     let point_sets = [[x_current],[x_current,x_next,x_last],[x_current,x_next]]

    // left and s_g2
    // right and g2
    // g2 is not negated as final_exponentiation is doing negation
    let g2 = generatorG2

    let x1Powers = powers(16, x1)
    let x4Powers = powers(4, x4)

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
              point_sets)

    let el = decompress(pi_term)

    let ml_l = miller_loop(el, g2_const)
    let ml_r = miller_loop(er, g2)

    final_exponentiation(ml_l, ml_r)
}

// this test generates random input data for verifier
test check_valid_proof_valid_public_inputs() {
    expect verifier(#"b68baf0d054502d95cc96bdf3bb8ec1c210eca4cb0abaf5c4c5f48e32e0bbf50af1be5dd04c877cb508ba8f098fda17d99322c291ffc757757d935d41a84ab84475ae9f016efe2b8f5d29732a969a4fe8ad026aa893ffd157b70795e34fb26d4ad7f044cf41b0d568845df07de9ffbf7bbb66c2b8211dabfffda7b3808d7e036b319692bd21f2331ea42f9bd2bc6c5f6b861e773fc8b013771ca49eb6a8272e6c16c7f68a7326af0fe597f7800d12c0fb78511af35eab2891d970468d192cfb488b398078824724710b64f060bfe20573ad987bc417df033c7dd1311a73233825b3564d642887c9dc21bc5865d858f91b57b8618bb136a30b29ff31cd100f24bef4fae7fb4fb8ad15557afd062d26074c80c0737793d3c2ae2badec03ec91a92b5516939aa6440befd435d562576f4e89b35f3835fc638b01803a81889afea0a741d4deba098ba32893e7c223e07adcaa1a4ba7b6a541a9237dfb5fd22408c35b949089cb0ae8778621e9dea83f830127668c9230508ea8f75b809aa08296fdea442a3fe6bc6426a495e7a2aec9289166be99812c38a9206a695780b5bd6a8e4297c69e6613a1884e8c78b524d0023d0adfd99b31be06c56ee01aaf46fa81a04779f055c9d72ab057cb870f26f0cc45556713d4765af11ed0677aa31e4fbd85d8b27f6881f9699025978d848d7d5bcde617a4325f3969b8eb637761fca2800a6af9b4f14cfa4f4dd28acce062ddeaaafaf256beac2b60b621af25a8b18cb692ef3433c00645b646bb1c2f4787b14f21ede56784d5df4ac0a9a549fdaebcfd0aaafb9cb6f88eb14853181baec79f1f61ddf2b1a5b8f28f63c4f5e51045a3356e8b485a0fd164632855eef21ce5a2cc469a5cd69fb5e348389b2d566c2acb5dfaef98adda4dd3809d374b794da4b2c1255a907e3c3383bfa79d89e1b22260b973e51d3f609d744d902f29114f00719273c7c599a27977c6dff03aa94bc6bf1d23237d8ae644606e1aa4027546f9a4e26041207f80f23e441ce618070e444ac78e8681ec0e89556068df9b7ef445cdc6d6111a9cf7ec3e595d57aec27aba5f5914ecc140975e70618c28b75c37e44159a6b74c97763921623286844e71df11bd098dd1c58f4b50e857b1169b87c7948ba2619bd5e01268683a94b44c7f77b50bd91877330df2a0baa0268da7ef36ca3d566058498a7948c680ec863f29a8052969b54465e96f0df1875f9cb0e04ccd146453c7c434803cae68be26e4af06dd54d8743820de35739cc2ef869ccae7f403c46a0126a09123f2baf3112595c480e45f2ff1b547335c0c1fd7a5e3f867fe0aa6744381b016fa1ce9cd6b6a313fe866a5223964ddc2286616c92a4e40f891bd46e4b4cac23de7c1c1c260dcdd4f52f4bd5161ef3ceb63ea09ecd63cc49cb037b2cfe13b770d95ed61cb1a7772aaf149c875bf18bae98c5764303a2389dd4475f2827eb0440da5bf80404ef9004b5854e998c2fcd7b8f1af5c6e1161e168ab9000ad33396cda9851e27e3a174cce67c6d208397b6a4e88c308e03fcc90b61005e63cad4cd64c672bdf45f2643000f6cb8f537e67af75c0cc7b6c45c4ed9e0c91b0a56396096e1fc71a1b79b58c531ba5ae3542d0f04bbbeabc21062de73cfe55745158184cd96696d3c9ef5fbaf712eabd10fdc84d4dab9295f1164aaacbb8a814747bb44b8f61b682973c741742c6b3999288c44c05807ecb5f5fe7c998461d74620d6a2f44159ac87e951ed9f4c96e00965d0508e1062e12af55e26208086136c2e56f2e9a43de32ae8f37f207de40a18e2c4a6f572585a7d816edcf223a63f5d8d6096094ea78bf7110656137200b6f81ec44a8f5f9e79ae20f087e1aa22ae3ac566315adea29501a03059c0d279b645a830a4567e144797f07b25343b6946307ca5993e311c7df098e35b1b1b1e50d679f8d52a74815f567761e9002707a73f9934d8370fe6b882b38e078e75499c68c0461fca81c1bbab4034d5c9db5a623d9aef69be0319d25f24a60c28a07a401bcebd5ae28524de0a3d5e12d0f4fa1511899f622f11308c27c2043d9fb14aabfbcdbbdd70f99ed09c41b3b08ff5ba2b092438fa29fa4cb04784fc3244ac9975f893f6e9d807b89f52e6d3446a9a905216c488e291e15ffddcee1fa4bf05c09a24d7f8b0245eb9ca0f9fa9121d5cb58644923d30b5b9ddfe71dfe1e24bdf75f84c7761875aff3fc371284f5b5c09866715656027275189bd3714b3ed90455c6cc559b9230018c35fb609d21130c803f96090ee00a4e0dedaf4de9e61d269771e732cf8df9d72de538c031c4672a3305c0db285f9b69f5b3f9291a78f328b8479e2e0036e3bce2cc0edeca81500be77accb604dd7297985c6dcb53e4989569bf60d15344fc6f7472b256af9b66100149a38cd79b33e7bdfe03ef5d8fa1224f7d02200b2c59698ecf7e85a97e82d04418ae8646fdc65d837382e1e698cc096d143254d0f83ec9af77c13bd7045f8b77b18c5208e6cdbb6dbedd4d8c79aa27be2e8208403036d40b6840f9d0a30969bf7c6f51cb057be4389958ddc4dba36875f3f92b164be7c4e6899a11e566452dac573a6", from_int(0x0000000000000000000000000000000000000000000000000000000000000001), from_int(0x000000000000000000000000000000000000000000000000000000000000303b)) == True
}

test check_proof_invalid_public_inputs(){
    expect verifier(#"b68baf0d054502d95cc96bdf3bb8ec1c210eca4cb0abaf5c4c5f48e32e0bbf50af1be5dd04c877cb508ba8f098fda17d99322c291ffc757757d935d41a84ab84475ae9f016efe2b8f5d29732a969a4fe8ad026aa893ffd157b70795e34fb26d4ad7f044cf41b0d568845df07de9ffbf7bbb66c2b8211dabfffda7b3808d7e036b319692bd21f2331ea42f9bd2bc6c5f6b861e773fc8b013771ca49eb6a8272e6c16c7f68a7326af0fe597f7800d12c0fb78511af35eab2891d970468d192cfb488b398078824724710b64f060bfe20573ad987bc417df033c7dd1311a73233825b3564d642887c9dc21bc5865d858f91b57b8618bb136a30b29ff31cd100f24bef4fae7fb4fb8ad15557afd062d26074c80c0737793d3c2ae2badec03ec91a92b5516939aa6440befd435d562576f4e89b35f3835fc638b01803a81889afea0a741d4deba098ba32893e7c223e07adcaa1a4ba7b6a541a9237dfb5fd22408c35b949089cb0ae8778621e9dea83f830127668c9230508ea8f75b809aa08296fdea442a3fe6bc6426a495e7a2aec9289166be99812c38a9206a695780b5bd6a8e4297c69e6613a1884e8c78b524d0023d0adfd99b31be06c56ee01aaf46fa81a04779f055c9d72ab057cb870f26f0cc45556713d4765af11ed0677aa31e4fbd85d8b27f6881f9699025978d848d7d5bcde617a4325f3969b8eb637761fca2800a6af9b4f14cfa4f4dd28acce062ddeaaafaf256beac2b60b621af25a8b18cb692ef3433c00645b646bb1c2f4787b14f21ede56784d5df4ac0a9a549fdaebcfd0aaafb9cb6f88eb14853181baec79f1f61ddf2b1a5b8f28f63c4f5e51045a3356e8b485a0fd164632855eef21ce5a2cc469a5cd69fb5e348389b2d566c2acb5dfaef98adda4dd3809d374b794da4b2c1255a907e3c3383bfa79d89e1b22260b973e51d3f609d744d902f29114f00719273c7c599a27977c6dff03aa94bc6bf1d23237d8ae644606e1aa4027546f9a4e26041207f80f23e441ce618070e444ac78e8681ec0e89556068df9b7ef445cdc6d6111a9cf7ec3e595d57aec27aba5f5914ecc140975e70618c28b75c37e44159a6b74c97763921623286844e71df11bd098dd1c58f4b50e857b1169b87c7948ba2619bd5e01268683a94b44c7f77b50bd91877330df2a0baa0268da7ef36ca3d566058498a7948c680ec863f29a8052969b54465e96f0df1875f9cb0e04ccd146453c7c434803cae68be26e4af06dd54d8743820de35739cc2ef869ccae7f403c46a0126a09123f2baf3112595c480e45f2ff1b547335c0c1fd7a5e3f867fe0aa6744381b016fa1ce9cd6b6a313fe866a5223964ddc2286616c92a4e40f891bd46e4b4cac23de7c1c1c260dcdd4f52f4bd5161ef3ceb63ea09ecd63cc49cb037b2cfe13b770d95ed61cb1a7772aaf149c875bf18bae98c5764303a2389dd4475f2827eb0440da5bf80404ef9004b5854e998c2fcd7b8f1af5c6e1161e168ab9000ad33396cda9851e27e3a174cce67c6d208397b6a4e88c308e03fcc90b61005e63cad4cd64c672bdf45f2643000f6cb8f537e67af75c0cc7b6c45c4ed9e0c91b0a56396096e1fc71a1b79b58c531ba5ae3542d0f04bbbeabc21062de73cfe55745158184cd96696d3c9ef5fbaf712eabd10fdc84d4dab9295f1164aaacbb8a814747bb44b8f61b682973c741742c6b3999288c44c05807ecb5f5fe7c998461d74620d6a2f44159ac87e951ed9f4c96e00965d0508e1062e12af55e26208086136c2e56f2e9a43de32ae8f37f207de40a18e2c4a6f572585a7d816edcf223a63f5d8d6096094ea78bf7110656137200b6f81ec44a8f5f9e79ae20f087e1aa22ae3ac566315adea29501a03059c0d279b645a830a4567e144797f07b25343b6946307ca5993e311c7df098e35b1b1b1e50d679f8d52a74815f567761e9002707a73f9934d8370fe6b882b38e078e75499c68c0461fca81c1bbab4034d5c9db5a623d9aef69be0319d25f24a60c28a07a401bcebd5ae28524de0a3d5e12d0f4fa1511899f622f11308c27c2043d9fb14aabfbcdbbdd70f99ed09c41b3b08ff5ba2b092438fa29fa4cb04784fc3244ac9975f893f6e9d807b89f52e6d3446a9a905216c488e291e15ffddcee1fa4bf05c09a24d7f8b0245eb9ca0f9fa9121d5cb58644923d30b5b9ddfe71dfe1e24bdf75f84c7761875aff3fc371284f5b5c09866715656027275189bd3714b3ed90455c6cc559b9230018c35fb609d21130c803f96090ee00a4e0dedaf4de9e61d269771e732cf8df9d72de538c031c4672a3305c0db285f9b69f5b3f9291a78f328b8479e2e0036e3bce2cc0edeca81500be77accb604dd7297985c6dcb53e4989569bf60d15344fc6f7472b256af9b66100149a38cd79b33e7bdfe03ef5d8fa1224f7d02200b2c59698ecf7e85a97e82d04418ae8646fdc65d837382e1e698cc096d143254d0f83ec9af77c13bd7045f8b77b18c5208e6cdbb6dbedd4d8c79aa27be2e8208403036d40b6840f9d0a30969bf7c6f51cb057be4389958ddc4dba36875f3f92b164be7c4e6899a11e566452dac573a6", from_int(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000), from_int(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffeffffcfc6)) == False
}

test check_invalid_proof_invalid_public_inputs(){
    expect verifier(#"b68baf0d054502d95cc96bdf3bb8ec1c210eca4cb0abaf5c4c5f48e32e0bbf50af1be5dd04c877cb508ba8f098fda17d99322c291ffc757757d935d41a84ab84475ae9f016efe2b8f5d29732a969a4fe8ad026aa893ffd157b70795e34fb26d4ad7f044cf41b0d568845df07de9ffbf7bbb66c2b8211dabfffda7b3808d7e036b319692bd21f2331ea42f9bd2bc6c5f6b861e773fc8b013771ca49eb6a8272e6c16c7f68a7326af0fe597f7800d12c0fb78511af35eab2891d970468d192cfb488b367078824724710b64f060bfe20573ad987bc417df033c7dd1311a73233825b3564d642887c9dc21bc5865d858f91b57b8618bb136a30b29ff31cd100f24bef4fae7fb4fb8ad15557afd062d26074c80c0737793d3c2ae2badec03ec91a92b5516939aa6440befd435d562576f4e89b35f3835fc638b01803a81889afea0a741d4deba098ba32893e7c223e07adcaa1a4ba7b6a541a9237dfb5fd22408c35b949089cb0ae8778621e9dea83f830127668c9230508ea8f75b809aa08296fdea442a3fe6bc6426a495e7a2aec9289166be99812c38a9206a695780b5bd6a8e4297c69e6613a1884e8c78b524d0023d0adfd99b31be06c56ee01aaf46fa81a04779f055c9d72ab057cb870f26f0cc45556713d4765af11ed0677aa31e4fbd85d8b27f6881f9699025978d848d7d5bcde617a4325f3969b8eb637761fca2800a6af9b4f14cfa4f4dd28acce062ddeaaafaf256beac2b60b621af25a8b18cb692ef3433c00645b646bb1c2f4787b14f21ede56784d5df4ac0a9a549fdaebcfd0aaafb9cb6f88eb14853181baec79f1f61ddf2b1a5b8f28f63c4f5e51045a3356e8b485a0fd164632855eef21ce5a2cc469a5cd69fb5e348389b2d566c2acb5dfaef98adda4dd3809d374b794da4b2c1255a907e3c3383bfa79d89e1b22260b973e51d3f609d744d902f29114f00719273c7c599a27977c6dff03aa94bc6bf1d23237d8ae644606e1aa4027546f9a4e26041207f80f23e441ce618070e444ac78e8681ec0e89556068df9b7ef445cdc6d6111a9cf7ec3e595d57aec27aba5f5914ecc140975e70618c28b75c37e44159a6b74c97763921623286844e71df11bd098dd1c58f4b50e857b1169b87c7948ba2619bd5e01268683a94b44c7f77b50bd91877330df2a0baa0268da7ef36ca3d566058498a7948c680ec863f29a8052969b54465e96f0df1875f9cb0e04ccd146453c7c434803cae68be26e4af06dd54d8743820de35739cc2ef869ccae7f403c46a0126a09123f2baf3112595c480e45f2ff1b547335c0c1fd7a5e3f867fe0aa6744381b016fa1ce9cd6b6a313fe866a5223964ddc2286616c92a4e40f891bd46e4b4cac23de7c1c1c260dcdd4f52f4bd5161ef3ceb63ea09ecd63cc49cb037b2cfe13b770d95ed61cb1a7772aaf149c875bf18bae98c5764303a2389dd4475f2827eb0440da5bf80404ef9004b5854e998c2fcd7b8f1af5c6e1161e168ab9000ad33396cda9851e27e3a174cce67c6d208397b6a4e88c308e03fcc90b61005e63cad4cd64c672bdf45f2643000f6cb8f537e67af75c0cc7b6c45c4ed9e0c91b0a56396096e1fc71a1b79b58c531ba5ae3542d0f04bbbeabc21062de73cfe55745158184cd96696d3c9ef5fbaf712eabd10fdc84d4dab9295f1164aaacbb8a814747bb44b8f61b682973c741742c6b3999288c44c05807ecb5f5fe7c998461d74620d6a2f44159ac87e951ed9f4c96e00965d0508e1062e12af55e26208086136c2e56f2e9a43de32ae8f37f207de40a18e2c4a6f572585a7d816edcf223a63f5d8d6096094ea78bf7110656137200b6f81ec44a8f5f9e79ae20f087e1aa22ae3ac566315adea29501a03059c0d279b645a830a4567e144797f07b25343b6946307ca5993e311c7df098e35b1b1b1e50d679f8d52a74815f567761e9002707a73f9934d8370fe6b882b38e078e75499c68c0461fca81c1bbab4034d5c9db5a623d9aef69be0319d25f24a60c28a07a401bcebd5ae28524de0a3d5e12d0f4fa1511899f622f11308c27c2043d9fb14aabfbcdbbdd70f99ed09c41b3b08ff5ba2b092438fa29fa4cb04784fc3244ac9975f893f6e9d807b89f52e6d3446a9a905216c488e291e15ffddcee1fa4bf05c09a24d7f8b0245eb9ca0f9fa9121d5cb58644923d30b5b9ddfe71dfe1e24bdf75f84c7761875aff3fc371284f5b5c09866715656027275189bd3714b3ed90455c6cc559b9230018c35fb609d21130c803f96090ee00a4e0dedaf4de9e61d269771e732cf8df9d72de538c031c4672a3305c0db285f9b69f5b3f9291a78f328b8479e2e0036e3bce2cc0edeca81500be77accb604dd7297985c6dcb53e4989569bf60d15344fc6f7472b256af9b66100149a38cd79b33e7bdfe03ef5d8fa1224f7d02200b2c59698ecf7e85a97e82d04418ae8646fdc65d837382e1e698cc096d143254d0f83ec9af77c13bd7045f8b77b18c5208e6cdbb6dbedd4d8c79aa27be2e8208403036d40b6840f9d0a30969bf7c6f51cb057be4389958ddc4dba36875f3f92b164be7c4e6899a11e566452dac573a6", from_int(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000), from_int(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffeffffcfc6)) == False
}

test check_valid_proof_trivial_public_inputs() {
    expect verifier(#"b68baf0d054502d95cc96bdf3bb8ec1c210eca4cb0abaf5c4c5f48e32e0bbf50af1be5dd04c877cb508ba8f098fda17d99322c291ffc757757d935d41a84ab84475ae9f016efe2b8f5d29732a969a4fe8ad026aa893ffd157b70795e34fb26d4ad7f044cf41b0d568845df07de9ffbf7bbb66c2b8211dabfffda7b3808d7e036b319692bd21f2331ea42f9bd2bc6c5f6b861e773fc8b013771ca49eb6a8272e6c16c7f68a7326af0fe597f7800d12c0fb78511af35eab2891d970468d192cfb488b398078824724710b64f060bfe20573ad987bc417df033c7dd1311a73233825b3564d642887c9dc21bc5865d858f91b57b8618bb136a30b29ff31cd100f24bef4fae7fb4fb8ad15557afd062d26074c80c0737793d3c2ae2badec03ec91a92b5516939aa6440befd435d562576f4e89b35f3835fc638b01803a81889afea0a741d4deba098ba32893e7c223e07adcaa1a4ba7b6a541a9237dfb5fd22408c35b949089cb0ae8778621e9dea83f830127668c9230508ea8f75b809aa08296fdea442a3fe6bc6426a495e7a2aec9289166be99812c38a9206a695780b5bd6a8e4297c69e6613a1884e8c78b524d0023d0adfd99b31be06c56ee01aaf46fa81a04779f055c9d72ab057cb870f26f0cc45556713d4765af11ed0677aa31e4fbd85d8b27f6881f9699025978d848d7d5bcde617a4325f3969b8eb637761fca2800a6af9b4f14cfa4f4dd28acce062ddeaaafaf256beac2b60b621af25a8b18cb692ef3433c00645b646bb1c2f4787b14f21ede56784d5df4ac0a9a549fdaebcfd0aaafb9cb6f88eb14853181baec79f1f61ddf2b1a5b8f28f63c4f5e51045a3356e8b485a0fd164632855eef21ce5a2cc469a5cd69fb5e348389b2d566c2acb5dfaef98adda4dd3809d374b794da4b2c1255a907e3c3383bfa79d89e1b22260b973e51d3f609d744d902f29114f00719273c7c599a27977c6dff03aa94bc6bf1d23237d8ae644606e1aa4027546f9a4e26041207f80f23e441ce618070e444ac78e8681ec0e89556068df9b7ef445cdc6d6111a9cf7ec3e595d57aec27aba5f5914ecc140975e70618c28b75c37e44159a6b74c97763921623286844e71df11bd098dd1c58f4b50e857b1169b87c7948ba2619bd5e01268683a94b44c7f77b50bd91877330df2a0baa0268da7ef36ca3d566058498a7948c680ec863f29a8052969b54465e96f0df1875f9cb0e04ccd146453c7c434803cae68be26e4af06dd54d8743820de35739cc2ef869ccae7f403c46a0126a09123f2baf3112595c480e45f2ff1b547335c0c1fd7a5e3f867fe0aa6744381b016fa1ce9cd6b6a313fe866a5223964ddc2286616c92a4e40f891bd46e4b4cac23de7c1c1c260dcdd4f52f4bd5161ef3ceb63ea09ecd63cc49cb037b2cfe13b770d95ed61cb1a7772aaf149c875bf18bae98c5764303a2389dd4475f2827eb0440da5bf80404ef9004b5854e998c2fcd7b8f1af5c6e1161e168ab9000ad33396cda9851e27e3a174cce67c6d208397b6a4e88c308e03fcc90b61005e63cad4cd64c672bdf45f2643000f6cb8f537e67af75c0cc7b6c45c4ed9e0c91b0a56396096e1fc71a1b79b58c531ba5ae3542d0f04bbbeabc21062de73cfe55745158184cd96696d3c9ef5fbaf712eabd10fdc84d4dab9295f1164aaacbb8a814747bb44b8f61b682973c741742c6b3999288c44c05807ecb5f5fe7c998461d74620d6a2f44159ac87e951ed9f4c96e00965d0508e1062e12af55e26208086136c2e56f2e9a43de32ae8f37f207de40a18e2c4a6f572585a7d816edcf223a63f5d8d6096094ea78bf7110656137200b6f81ec44a8f5f9e79ae20f087e1aa22ae3ac566315adea29501a03059c0d279b645a830a4567e144797f07b25343b6946307ca5993e311c7df098e35b1b1b1e50d679f8d52a74815f567761e9002707a73f9934d8370fe6b882b38e078e75499c68c0461fca81c1bbab4034d5c9db5a623d9aef69be0319d25f24a60c28a07a401bcebd5ae28524de0a3d5e12d0f4fa1511899f622f11308c27c2043d9fb14aabfbcdbbdd70f99ed09c41b3b08ff5ba2b092438fa29fa4cb04784fc3244ac9975f893f6e9d807b89f52e6d3446a9a905216c488e291e15ffddcee1fa4bf05c09a24d7f8b0245eb9ca0f9fa9121d5cb58644923d30b5b9ddfe71dfe1e24bdf75f84c7761875aff3fc371284f5b5c09866715656027275189bd3714b3ed90455c6cc559b9230018c35fb609d21130c803f96090ee00a4e0dedaf4de9e61d269771e732cf8df9d72de538c031c4672a3305c0db285f9b69f5b3f9291a78f328b8479e2e0036e3bce2cc0edeca81500be77accb604dd7297985c6dcb53e4989569bf60d15344fc6f7472b256af9b66100149a38cd79b33e7bdfe03ef5d8fa1224f7d02200b2c59698ecf7e85a97e82d04418ae8646fdc65d837382e1e698cc096d143254d0f83ec9af77c13bd7045f8b77b18c5208e6cdbb6dbedd4d8c79aa27be2e8208403036d40b6840f9d0a30969bf7c6f51cb057be4389958ddc4dba36875f3f92b164be7c4e6899a11e566452dac573a6", from_int(0x0000000000000000000000000000000000000000000000000000000000000001), from_int(0x0000000000000000000000000000000000000000000000000000000000000001)) == False
}
