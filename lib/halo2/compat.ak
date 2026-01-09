//// Compatibility layer for Halo2 verifier library
//// Provides functions that existed in older Aiken stdlib versions

use aiken/builtin.{
  bls12_381_final_verify, bls12_381_miller_loop, bytearray_to_integer,
  integer_to_bytearray,
}
use aiken/collection/list.{reverse}
use aiken/crypto/bls12_381/g1.{
  decompress as decompress_g1, generator as g1_generator, scale as scaleG1,
  sub as subG1, zero as zeroG1,
}
use aiken/crypto/bls12_381/g2.{
  decompress as decompress_g2, generator as g2_generator, scale as scaleG2,
}
use aiken/crypto/bls12_381/scalar.{
  Scalar, field_prime, new, scale as scaleScalar, sub, to_int,
}
use aiken/primitive/bytearray

/// Type alias - State<Scalar> is now just Scalar in newer Aiken versions
pub type State<a> =
  a

/// Construct a Scalar from an Int, reducing modulo the field prime
/// This replaces the old from_int function
pub fn from_int(n: Int) -> Scalar {
  // Handle negative numbers by adding field_prime
  let normalized = n % field_prime
  let final_val =
    if normalized < 0 {
      normalized + field_prime
    } else {
      normalized
    }
  // Use stdlib new() to construct the Scalar
  expect Some(s) = new(final_val)
  s
}

/// Construct a Scalar from little-endian bytes
pub fn from_bytes_little_endian(bytes: ByteArray) -> Scalar {
  let len = bytearray.length(bytes)
  // Only trace details for x squeeze (773 bytes accumulated -> 32 byte hash)
  // We identify x by the first byte being 0x92
  let first_byte = bytearray.at(bytes, 0)
  let n = bytearray_to_integer(False, bytes)
  when first_byte is {
    0x92 -> {
      trace @"DEBUG x squeeze byte[0]": bytearray.at(bytes, 0)
      trace @"DEBUG x squeeze byte[1]": bytearray.at(bytes, 1)
      trace @"DEBUG x squeeze byte[2]": bytearray.at(bytes, 2)
      trace @"DEBUG x squeeze byte[14]": bytearray.at(bytes, 14)
      trace @"DEBUG x squeeze byte[15]": bytearray.at(bytes, 15)
      trace @"DEBUG x squeeze full": bytes
      trace @"DEBUG x squeeze integer": n
      Void
    }
    _ -> Void
  }
  from_int(n)
}

/// Convert a Scalar to little-endian bytes (32 bytes for BLS12-381)
pub fn to_bytes_little_endian(s: Scalar) -> ByteArray {
  let n = to_int(s)
  integer_to_bytearray(False, 32, n)
}

/// Subtract an integer from a Scalar
pub fn sub_int(s: Scalar, n: Int) -> Scalar {
  sub(s, from_int(n))
}

/// Type alias for the continuation function in fold2 operations
pub type Fold2<a, b, result> =
  fn(a, b) -> result

/// Right fold with two accumulators (CPS style)
/// Processes the list from right to left, maintaining two separate accumulator values
/// NOTE: Due to CPS style, the final order depends on how push is used in the callback.
/// Current behavior: processes in order [0, 1, 2] but push prepends, so result is [2, 1, 0]
pub fn foldr2(
  self: List<elem>,
  zero_a: a,
  zero_b: b,
  with: fn(elem, a, b, Fold2<a, b, result>) -> result,
  return: Fold2<a, b, result>,
) -> result {
  // CPS style builds continuations that process in reverse order:
  // do_foldr2([A, B, C]) -> calls with(C, ...) first, then with(B, ...), then with(A, ...)
  // With push prepending: result is [A_result, B_result, C_result] (original order!)
  do_foldr2(self, with, return)(zero_a, zero_b)
}

fn do_foldr2(
  reversed: List<elem>,
  with: fn(elem, a, b, Fold2<a, b, result>) -> result,
  return: Fold2<a, b, result>,
) -> Fold2<a, b, result> {
  when reversed is {
    [] -> return
    [x, ..xs] -> do_foldr2(xs, with, fn(a, b) { with(x, a, b, return) })
  }
}

// ============================================================================
// BLS12-381 Pairing Functions
// ============================================================================

/// Compute the Miller loop for BLS12-381 pairing
/// Wrapper around the builtin miller_loop function
pub fn miller_loop(g1: G1Element, g2: G2Element) -> MillerLoopResult {
  bls12_381_miller_loop(g1, g2)
}

/// Final exponentiation for BLS12-381 pairing check
/// Takes two miller loop results and checks if they pair to the same value
/// Returns True if e(g1_a, g2_a) == e(g1_b, g2_b)
pub fn final_exponentiation(
  ml_a: MillerLoopResult,
  ml_b: MillerLoopResult,
) -> Bool {
  bls12_381_final_verify(ml_a, ml_b)
}

// ============================================================================
// Pairing Tests
// ============================================================================

/// Test: e(g1, g2) == e(g1, g2) should be true
/// But if final_verify checks ml1 * ml2 == 1, this would be False
/// (because e(g1,g2) * e(g1,g2) = e(g1,g2)^2 != 1)
test pairing_identity_test() {
  let g1 = g1_generator
  let g2 = g2_generator
  let ml1 = miller_loop(g1, g2)
  let ml2 = miller_loop(g1, g2)
  trace @"pairing_identity result": final_exponentiation(ml1, ml2)
  final_exponentiation(ml1, ml2)
}

/// Test: e(g1, g2) vs e(-g1, g2) - these are NOT equal
/// bls12_381_final_verify checks EQUALITY, not product identity
/// So final_verify(e(g1,g2), e(-g1,g2)) returns False because e(g1,g2) != e(-g1,g2)
test pairing_product_check_test() fail {
  let g1 = g1_generator
  let g2 = g2_generator
  let neg_g1 = subG1(zeroG1, g1)
  let ml1 = miller_loop(g1, g2)
  // e(g1, g2)
  let ml2 = miller_loop(neg_g1, g2)
  // e(-g1, g2) = e(g1, g2)^(-1)
  trace @"pairing_product_check result (False because equality check, not product)": final_exponentiation(
    ml1,
    ml2,
  )
  // This returns False because final_verify checks equality, and e(g1,g2) != e(-g1,g2)
  // Test is marked 'fail' because we expect the expression to evaluate to False
  final_exponentiation(ml1, ml2)
}

/// Test: e(g1, g2) == e(-g1, g2) should be FALSE (opposite sign)
test pairing_negation_test() {
  let g1 = g1_generator
  let g2 = g2_generator
  let neg_g1 = subG1(zeroG1, g1)
  let ml1 = miller_loop(g1, g2)
  let ml2 = miller_loop(neg_g1, g2)
  // These should NOT be equal
  !final_exponentiation(ml1, ml2)
}

/// Test: final_verify checks equality, so e(g1, g2) vs e(g1, g2) * e(-g1, g2) behavior
/// If final_verify(a, b) checks a == b, then with negation it should fail
/// If final_verify(a, b) checks a * b == 1, then e(g1, g2) * e(-g1, g2) == 1 should pass
test pairing_product_identity_test() fail {
  let g1 = g1_generator
  let g2 = g2_generator
  let neg_g1 = subG1(zeroG1, g1)
  let ml1 = miller_loop(g1, g2)
  // e(g1, g2)
  let ml2 = miller_loop(neg_g1, g2)
  // e(-g1, g2) = e(g1, g2)^(-1)
  // If final_verify checks ml1 * ml2 == 1, this returns True
  // If final_verify checks ml1 == ml2, this returns False
  // The result tells us the semantics!
  trace @"pairing_product_identity result": final_exponentiation(ml1, ml2)
  // This SHOULD fail because final_verify checks equality, not product identity
  final_exponentiation(ml1, ml2)
}

/// Test: Check pairing bilinearity e(s*G1, G2) = e(G1, s*G2)
/// This tests that scalar multiplication works correctly with pairings
test pairing_bilinearity_test() {
  let g1 = g1_generator
  let g2 = g2_generator

  // Use a small scalar for the test
  let s = new(12345)
  expect Some(scalar_val) = s

  // Compute e(s*G1, G2) and e(G1, s*G2)
  let sg1 = scaleG1(g1, scalar_val)
  let sg2 = scaleG2(g2, scalar_val)

  let ml1 = miller_loop(sg1, g2)
  // e(s*G1, G2)
  let ml2 = miller_loop(g1, sg2)

  // e(G1, s*G2)
  trace @"bilinearity test - e(s*G1, G2) vs e(G1, s*G2)"
  let result = final_exponentiation(ml1, ml2)
  trace @"bilinearity result": result
  result
}

/// Test with the actual verification points from our proof
/// This tests if the pairing check works with non-generator points
test pairing_verification_points_test() fail {
  // These are the exact compressed points from our verification test
  // el (pi_term) from trace
  let el =
    decompress_g1(
      #"998aaf1936048b278e520bb05389122ba95e057fec2133603a27b7b2ae6d12f17c5a6f4fbc837d3bf2d4c93e77c549a4",
    )

  // er (msm result) from trace - this is a G1 point
  let er_g1 =
    decompress_g1(
      #"a81a0c6b053d27c2c88931cfacd99fe18deb8f31020769eb86056b598e00a220851d1cd510793ce832bd5eb28397f2f2",
    )

  // g2_const (s*G2) from trace
  let g2_const =
    decompress_g2(
      #"ac5388c41846b099d717048176e9a71024f44836b11787900681b34b9b283fa7c9d0822109d9d4b2be820267fe064e000742abcf269919cb58e1479acf29a667cc7a5b333214a7b03adf5f5b514fc1d374cfd099714c864c23fff5fa77c4a0c2",
    )

  // G2 generator from trace
  let g2_gen =
    decompress_g2(
      #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
    )

  trace @"Testing with actual verification points"

  // Compute e(el, g2_const) and e(er, g2_gen)
  let ml_l = miller_loop(el, g2_const)
  let ml_r = miller_loop(er_g1, g2_gen)

  let result = final_exponentiation(ml_l, ml_r)
  trace @"verification points result": result

  // This test is marked fail because we expect False
  // If it returns True, the test will fail
  result
}
