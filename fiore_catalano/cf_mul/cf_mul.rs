use num_bigint::BigUint;
use crate::paillier::p_encrypt::p_encrypt::p_encrypt;
use crate::paillier::p_keygen::PublicKey;
use crate::crypto_error::CryptoError;


pub fn cf_mul (
	ciphert: &(BigUint, BigUint),
	ciphert1: &(BigUint, BigUint), 
	pk: &PublicKey,
) -> Result<(BigUint, BigUint, BigUint), CryptoError> {


	let c0 = &ciphert.0;

	let c1 = &ciphert.1;

	let c0_p = &ciphert1.0;
	
	let c1_p = &ciphert1.1;

	let product_c0 = (c0 * c0_p) % &pk.n;

	let enc_product = p_encrypt(&product_c0, pk)?;

	let c1c0_p = c1.modpow(c0_p, &pk.n_squared);

	let c1_pc0 = c1_p.modpow(c0, &pk.n_squared);

	let c0_snd = ((&enc_product * c1c0_p) % &pk.n_squared * c1_pc0) % &pk.n_squared;


	let c1_snd = c1.clone();
	let c2_snd = c1_p.clone();


	Ok((c0_snd, c1_snd, c2_snd))


}
