//// Compatibility layer for Halo2 verifier library
//// Provides functions that existed in older Aiken stdlib versions

use aiken/builtin.{
  bls12_381_final_verify, bls12_381_miller_loop, bytearray_to_integer,
  integer_to_bytearray,
}
use aiken/collection/list.{reverse}
use aiken/crypto/bls12_381/scalar.{Scalar, field_prime, new, sub, to_int}

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
  let n = bytearray_to_integer(False, bytes)
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
pub fn foldr2(
  self: List<elem>,
  zero_a: a,
  zero_b: b,
  with: fn(elem, a, b, Fold2<a, b, result>) -> result,
  return: Fold2<a, b, result>,
) -> result {
  do_foldr2(reverse(self), with, return)(zero_a, zero_b)
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
