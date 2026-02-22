use num_bigint::BigUint;

//

pub fn cf_add(
	ciphert0: &(BigUint, BigUint), 
	ciphert1: &(BigUint, BigUint),
	n: &BigUint,
	n_squared: &BigUint,
) -> (BigUint, BigUint) {

	let c0 = &ciphert0.0;

	let c1 = &ciphert1.0;

	let c0_p = &ciphert1.0;

	let c1_p = &ciphert1.1;

	let c0_snd = (c0 + c0_p) % n;

	let c1_snd = (c1 * c1_p) % n_squared;

	(c0_snd, c1_snd)


}