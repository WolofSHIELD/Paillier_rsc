
use crate::paillier::p_decrypt::p_decrypt::p_decrypt;
use crate::paillier::p_keygen::p_keygen::SecretKey;
use crate::paillier::p_keygen::PublicKey;
use num_bigint::BigUint;
use crate::crypto_error::crypto_error::CryptoError;


pub fn cf_add_dec(
	ciphert: &(BigUint, BigUint), 
	pk : &PublicKey, 
	sk : &SecretKey,
) -> Result<BigUint, CryptoError> {


	let c0 = &ciphert.0;

	let c1 = &ciphert.1;

	// Déchiffrer les deux composants ciphertext :
	//let dec_c0 = p_decrypt(&c0, pk, sk)?; // somme de (t*t' - bi*b'i)
	let dec_masque = p_decrypt(&c1, pk, sk)?; // somme de (bi*b'i)

	// message = somme des (t*t' - bi*b'i) + somme des (bi*b'i) = somme t*t'
	let message = (c0 + dec_masque) % &pk.n;

	Ok(message)


}