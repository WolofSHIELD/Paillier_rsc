use crate::paillier::p_encrypt::p_encrypt::p_encrypt;
use num_bigint::BigUint;
use crate::paillier::p_keygen::PublicKey;



pub fn masque_encrypt(masque: &BigUint, pk: &PublicKey) -> Result<BigUint, &'static str> {


	let mask_encrypt_b = p_encrypt(&masque, pk);

	Ok(mask_encrypt_b)

}  
