
use crate::paillier::p_decrypt::p_decrypt::p_decrypt;
use crate::paillier::p_keygen::p_keygen::SecretKey;
use crate::paillier::p_keygen::PublicKey;
use num_bigint::BigUint;
use crate::crypto_error::CryptoError;


pub fn cf_add_dec(
	ciphert: &(BigUint, BigUint), 
	pk : &PublicKey, 
	sk : &SecretKey,
) -> Result<BigUint, CryptoError> {


	let c0 = &ciphert.0;

	let c1 = &ciphert.1;

	let dec_masque = p_decrypt(&c1, pk, sk)?;

	let message = (c0 + dec_masque) % &pk.n;

	Ok(message)	


}