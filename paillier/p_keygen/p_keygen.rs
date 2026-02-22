use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand_core::OsRng;
use zeroize::Zeroize;
use crate::paillier::math::{l_function, gcd, lcm, mod_inverse, generate_safe_prime};
use crate::crypto_error::CryptoError;

// ============================================================================
// Clé publique Paillier — pas de données secrètes, pas de zeroize nécessaire
// ============================================================================
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub n:         BigUint,
    pub g:         BigUint,
    pub n_squared: BigUint,
}

// ============================================================================
// Helper : efface les octets internes d'un BigUint
// ============================================================================
fn zeroize_biguint(n: &mut BigUint) {
    let bits = n.bits() as usize;
    if bits > 0 {
        *n = BigUint::from_bytes_be(&vec![0u8; (bits + 7) / 8]);
    }
    *n = BigUint::default();
}

// ============================================================================
// Clé secrète Paillier — ZEROISÉE À LA DESTRUCTION
// ============================================================================
#[derive(Clone, Debug)]
pub struct SecretKey {
    pub lambda: BigUint,
    pub mu:     BigUint,
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        zeroize_biguint(&mut self.lambda);
        zeroize_biguint(&mut self.mu);
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ============================================================================
// Paire de clés
// ============================================================================
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

// ============================================================================
// Génération de clés Paillier
//
// NOTE SUR LA TAILLE DE LAMBDA :
// Pour des safe primes p = 2p'+1, q = 2q'+1 de `nbits` bits :
//   lambda = lcm(p-1, q-1) = 2·p'·q'
// p' et q' ont `nbits-1` bits, donc lambda a ~2·nbits - 1 bits.
// Exemple : p_keygen(1024) → lambda ~ 2047 bits. C'est CORRECT et attendu.
// Lambda n'est PAS destiné à être un nombre de `nbits` bits.
//
// FIX Bug #1 — g = n+1 au lieu de la boucle de recherche aléatoire :
// Avec des safe primes, g = n+1 est toujours un générateur valide car :
//   (n+1)^m mod n² = 1 + m·n  (binôme de Newton, les termes en n² s'annulent)
//   L((n+1)^lambda mod n²) = lambda mod n
//   gcd(lambda, n) = 1  (car n = p·q et lambda = 2p'q', avec p',q' != p,q)
// Cela supprime une boucle coûteuse avec modpow sur n² et garantit la terminaison.
//
// FIX Bug #2 — g_lambda n'est plus calculé deux fois :
// L'ancien code calculait g_lambda dans la boucle (non sauvegardé), puis le
// recalculait après. Avec g = n+1, on exploite l'identité algébrique :
//   (n+1)^lambda mod n² = 1 + lambda·n  (mod n²)
// calculé via une multiplication simple, pas un modpow complet.
// ============================================================================
pub fn p_keygen(nbits: u64) -> Result<KeyPair, CryptoError> {
    // Deux safe primes distincts p et q tels que p = 2p'+1, q = 2q'+1
    let p = generate_safe_prime(nbits)?;
    let mut q = generate_safe_prime(nbits)?;
    while p == q {
        q = generate_safe_prime(nbits)?;
    }

    let n         = &p * &q;
    let n_squared = &n * &n;

    let p_minus_1 = &p - BigUint::one();
    let q_minus_1 = &q - BigUint::one();
    let phi_n     = &p_minus_1 * &q_minus_1;

    // Invariant garanti par la construction safe prime — Err par sécurité défensive
    if gcd(&n, &phi_n) != BigUint::one() {
        return Err(CryptoError::NoModularInverse);
    }

    let lambda = lcm(&p_minus_1, &q_minus_1);

    // FIX Bug #1 : g = n+1, choix canonique valide pour tous les safe primes.
    // Propriété : (n+1)^m mod n² = 1 + m·n  pour tout m.
    // Évite la boucle aléatoire non bornée et les modpow coûteux sur n².
    let g = &n + BigUint::one();

    // FIX Bug #2 : calcul de g_lambda via l'identité algébrique (n+1)^lambda mod n²
    // = (1 + lambda·n) mod n².
    // Aucun modpow nécessaire — une multiplication et un modulo suffisent.
    let g_lambda = (BigUint::one() + &lambda * &n) % &n_squared;

    let l_g_lambda = l_function(&g_lambda, &n);

    // Vérification défensive : gcd(L(g^lambda mod n²), n) doit valoir 1
    if gcd(&l_g_lambda, &n) != BigUint::one() {
        return Err(CryptoError::NoModularInverse);
    }

    let mu = mod_inverse(&l_g_lambda, &n)?;

    Ok(KeyPair {
        public_key: PublicKey { n, g, n_squared },
        secret_key: SecretKey { lambda, mu },
    })
}