use num_bigint::BigUint;

use crate::montgomery::montgomery::multiple_precision_mul;
use crate::paillier::p_keygen::PublicKey;
//

pub fn cf_add(
	ciphert0: &(BigUint, BigUint), 
	ciphert1: &(BigUint, BigUint),
	_n: &BigUint,
	n_squared: &BigUint,
) -> (BigUint, BigUint) {

	
	let pk = PublicKey {
		n: _n.clone(),
		g: BigUint::default(), // g n'est pas utilisé dans cette fonction
		n_squared: n_squared.clone(),
	};

	let c0 = &ciphert0.0;

	let c1 = &ciphert0.1;

	let c0_p = &ciphert1.0;

	let c1_p = &ciphert1.1;

	// Dans la version correcte, les deux composantes sont des chiffrem
	// ents Paillier (mod n^2) et l'agrégation est réalisée en multipliant
	// les ciphertexts (correspond à l'addition des plaintexts).
	let c0_snd = (c0 + c0_p) % &pk.n;

	let c1_snd = multiple_precision_mul(c1, c1_p, &pk).unwrap() % &pk.n_squared;
	
	(c0_snd, c1_snd)


}