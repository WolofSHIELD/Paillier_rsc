use num_bigint::BigUint;
use crate::paillier::p_decrypt::p_decrypt::p_decrypt;
use crate::paillier::p_keygen::p_keygen::SecretKey;
use crate::paillier::p_keygen::PublicKey;
use crate::crypto_error::CryptoError;



pub fn cf_mul_dec(
	ciphert: &(BigUint, BigUint, BigUint), 
	pk: &PublicKey, 
	sk: &SecretKey,
) -> Result<BigUint, CryptoError> {


	let c0 = &ciphert.0;

	let c1 = &ciphert.1;

	let c2 = &ciphert.2;

	let dec_c0 = p_decrypt(c0, pk, sk)?;

	let dec_c1 = p_decrypt(c1, pk, sk)?;

	let dec_c2 = p_decrypt(c2, pk, sk)?;

	let result_snd = (dec_c0 + dec_c1 * dec_c2) % &pk.n;

	
	Ok(result_snd)


}  
