use num_bigint::BigUint;
use crate::crypto_error::crypto_error::CryptoError;
//use crate::paillier::p_keygen::p_keygen::SecretKey;
use crate::paillier::p_keygen::PublicKey;
pub use crate::paillier::math::{l_function, gcd, generate_safe_prime, mod_inverse, lcm};

pub fn multiple_precision_mul(a: &BigUint, b: &BigUint, pk: &PublicKey) -> Result<BigUint, CryptoError> {
    // Use Karatsuba multiplication for better efficiency with large numbers
    Ok(karatsuba_mul(a, b, &pk.n))
}



pub fn karatsuba_mul(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    let a_bits = a.bits();
    let b_bits = b.bits();
    
    // Use schoolbook for small numbers
    if a_bits < 64 || b_bits < 64 {
        return (a * b) % n;
    }
    
    let k = std::cmp::max(a_bits, b_bits) / 2;
    let base = BigUint::from(1u32) << k;
    
    let (a_high, a_low) = (a >> k, a % &base);
    let (b_high, b_low) = (b >> k, b % &base);
    
    let z0 = montgomery_reduce(&(&a_low * &b_low), n);
    let z2: BigUint = montgomery_reduce(&(&a_high * &b_high), n);
    let big_uint = &a_low + &a_high;
    let z1 = montgomery_reduce(&(big_uint * (&b_low + &b_high)), n);
    let z1 = ((z1 + n + n - &z0) % n - &z2 + n) % n;
    
    ((z2 << (2 * k)) + (z1 << k) + z0) % n
}

fn montgomery_reduce(t: &BigUint, n: &BigUint) -> BigUint {
    let r = BigUint::from(1u32) << (n.bits());
    let r_inv = mod_inverse(&r, n).unwrap_or_default();
    (t * &r_inv) % n
}



