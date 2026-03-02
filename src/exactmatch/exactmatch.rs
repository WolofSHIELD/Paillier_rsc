// =========================================================
// ExactMatch — PSI (cardinal d'intersection des bases de donénes)
// via Catalano-Fiore (1 niveau de Mul)
//

//   (1) Hash 30 bits, table creuse.
//   (2) Serveur ne reçoit jamais les masques en clair.
//   (3) n1 != n2 : phase2 prend kp1 ET kp2, génère des
//        masques distincts dans Z_{n1} et Z_{n2}.
//   (4) Serveur conserve les triplets (pas de relinéarisation).
//   (5) Phase 4 : cf_mul_dec (Dec2) + somme.
// =========================================================

use num_bigint::{BigUint, RandBigInt};
use rand_core::OsRng;
use crate::paillier::p_keygen::PublicKey;
use std::collections::{HashMap, HashSet};
use std::time::Instant;


// ---------------------------------------------------------------------------
use crate::fiore_catalano::cf_mul::cf_mul::cf_mul;
use crate::fiore_catalano::cf_mul_dec::cf_mul_dec::cf_mul_dec;
use crate::paillier::p_encrypt::p_encrypt::p_encrypt;
use crate::paillier::p_keygen::p_keygen::p_keygen;
use crate::KeyPair;

// ---------------------------------------------------------
// Constantes
// ---------------------------------------------------------

pub const HASH_BITS:  usize = 30;
pub const TABLE_SIZE: usize = 1 << HASH_BITS;

// ---------------------------------------------------------
// Types alias
// ---------------------------------------------------------

/// CF Premiere Forme : (c0, c1)
/// c0 = m - b mod n,  c1 = Enc_pk(b)
pub type CfFst = (BigUint, BigUint);

/// CF Seconde Forme : (c0'', c1'', c2'')
pub type CfSnd = (BigUint, BigUint, BigUint);

// ---------------------------------------------------------
// Table creuse
// ---------------------------------------------------------

pub struct SparseTable {
    pub active: HashSet<usize>,
}

impl SparseTable {
    pub fn build(nss_list: &[String]) -> Self {
        let mut active = HashSet::new();
        for nss in nss_list {
            active.insert(simple_hash(nss));
        }
        SparseTable { active }
    }

    pub fn len(&self) -> usize {
        self.active.len()
    }

    pub fn common_positions(&self, other: &SparseTable) -> Vec<usize> {
        let (small, big) = if self.active.len() <= other.active.len() {
            (&self.active, &other.active)
        } else {
            (&other.active, &self.active)
        };
        small.iter().filter(|p| big.contains(p)).copied().collect()
    }
}

// ---------------------------------------------------------
// Bundles
//
// Chaque BD produit des Ft chiffres SOUS
// pk1 ET sous pk2. Le serveur fait ensuite CF.Mul en utilisant
// le meme module n pour les deux operandes.
// ---------------------------------------------------------

pub struct FtBundle {
    pub ft_by_pos: HashMap<usize, CfFst>,
}

pub struct DualFtBundle {
    pub under_pk1: FtBundle,
    pub under_pk2: FtBundle,
}

// ---------------------------------------------------------
// Hash (remplacer par SHA-256/BLAKE3 en production)
// ---------------------------------------------------------

pub fn simple_hash(s: &str) -> usize {
    let mut h: u32 = 0;
    for ch in s.chars() {
        h = h.wrapping_shl(7).wrapping_sub(h).wrapping_add(ch as u32);
    }
    (h as usize) & (TABLE_SIZE - 1)
}

// ---------------------------------------------------------
// Chargement CSV — colonne "NSS"
// ---------------------------------------------------------

pub fn load_nss_from_csv(path: &str) -> Vec<String> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(path)
        .unwrap_or_else(|e| panic!("Impossible d'ouvrir {} : {}", path, e));
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let header = lines.next().expect("Fichier vide").expect("Erreur lecture");
    let cols: Vec<&str> = header.split(',').collect();
    let nss_col = cols
        .iter()
        .position(|c| c.trim() == "NSS")
        .expect("Colonne 'NSS' introuvable");

    lines
        .filter_map(|line| {
            let line = line.ok()?;
            let val = line.split(',').nth(nss_col)?.trim().to_string();
            if val.is_empty() { None } else { Some(val) }
        })
        .collect()
}

// ---------------------------------------------------------
// Phase 0 — KeyGen
// ---------------------------------------------------------

pub fn phase0_keygen(label: &str, bits: u64) -> KeyPair {
    println!("  [Phase 0] {} : generation des cles ({} bits)...", label, bits);
    let t = Instant::now();
    let kp = p_keygen(bits).expect("p_keygen a echoue");
    println!("  [Phase 0] {} : cles generees en {:.3?}", label, t.elapsed());
    kp
}

// ---------------------------------------------------------
// Phase 1 — Table creuse
// ---------------------------------------------------------

pub fn phase1_build_table(label: &str, nss_list: &[String]) -> SparseTable {
    println!(
        "  [Phase 1] {} : {} NSS, TABLE_SIZE=2^{}...",
        label, nss_list.len(), HASH_BITS
    );
    let table = SparseTable::build(nss_list);
    println!("  [Phase 1] {} : {} position(s) active(s).", label, table.len());
    table
}

// ---------------------------------------------------------
// Helper : CF.Enc(1, b) = ( (1 - b) mod n, Enc_pk(b) )
// ---------------------------------------------------------

// ---------------------------------------------------------
// Helper : CF.Enc(1, b) sous une PublicKey donnée
// Raison : le chiffrement ne nécessite que n, g, n_squared.
// ---------------------------------------------------------
fn make_ft_for_one(b: &BigUint, pk: &crate::paillier::p_keygen::PublicKey) -> CfFst {
    let n     = &pk.n;
    let b_mod = b % n;
    let c0    = (BigUint::from(1u32) + n - &b_mod) % n;
    let c1    = p_encrypt(&b_mod, pk).expect("p_encrypt(b) a echoue");
    (c0, c1)
}

// ---------------------------------------------------------
// Phase 2 — Preparation des Ft
//
// REFACTORING : prend &PublicKey
// Raison : le chiffrement (p_encrypt) n'utilise que pk.n, pk.g,
// pk.n_squared — jamais la SecretKey. Dans un déploiement réel
// sur machines distantes, chaque BD ne possède que la clé
// PUBLIQUE de l'autre BD (reçue via le serveur en Phase 0b).
// Passer un &KeyPair entier serait une fausse abstraction car
// on n'aurait pas la SecretKey de l'autre BD — et c'est correct,
// le déchiffrement (Phase 4) se fait exclusivement avec kp_self.
//
// Dans client.rs :
//   let (pk1, pk2) = if bd_id == 1 {
//       (&kp_self.public_key, &pk_other)   // pk_other = PublicKey reçue
//   } else {
//       (&pk_other, &kp_self.public_key)
//   };
//   let bundle = phase2_prepare_dual_ft(&label, &table, pk1, pk2);
// ---------------------------------------------------------

pub fn phase2_prepare_dual_ft(
    label: &str,
    table: &SparseTable,
    pk1:   &crate::paillier::p_keygen::PublicKey,
    pk2:   &crate::paillier::p_keygen::PublicKey,
) -> DualFtBundle {
    println!(
        "  [Phase 2] {} : preparation Ft pour {} positions (sous pk1 et pk2)...",
        label, table.len()
    );

    let mut rng = OsRng;
    let mut ft_pk1: HashMap<usize, CfFst> = HashMap::with_capacity(table.len());
    let mut ft_pk2: HashMap<usize, CfFst> = HashMap::with_capacity(table.len());

    for &pos in table.active.iter() {
        // Masque b1 tiré dans Z_{n1} → Ft chiffré sous pk1
        let b1 = rng.gen_biguint_below(&pk1.n);
        ft_pk1.insert(pos, make_ft_for_one(&b1, pk1));

        // Masque b2 tiré dans Z_{n2} → Ft chiffré sous pk2
        // b2 est indépendant de b1 : n1 ≠ n2 en général
        let b2 = rng.gen_biguint_below(&pk2.n);
        ft_pk2.insert(pos, make_ft_for_one(&b2, pk2));
    }

    println!("  [Phase 2] {} : Ft prets (le serveur ne voit jamais b en clair).", label);

    DualFtBundle {
        under_pk1: FtBundle { ft_by_pos: ft_pk1 },
        under_pk2: FtBundle { ft_by_pos: ft_pk2 },
    }
}

// ---------------------------------------------------------
// Phase 3 — Serveur : CF.Mul sur les positions communes
// ---------------------------------------------------------

pub fn phase3_server_compute(
    table1: &SparseTable,
    table2: &SparseTable,
    bd1:    &DualFtBundle,
    bd2:    &DualFtBundle,
    kp1:    &KeyPair,
    kp2:    &KeyPair,
) -> (Vec<CfSnd>, Vec<CfSnd>) {
    println!("  [Phase 3] Serveur : CF.Mul sur les positions communes...");
    let t_start = Instant::now();

    let common = table1.common_positions(table2);
    println!("  [Phase 3] {} position(s) commune(s).", common.len());

    let mut out_pk1: Vec<CfSnd> = Vec::with_capacity(common.len());
    let mut out_pk2: Vec<CfSnd> = Vec::with_capacity(common.len());

    for pos in common.iter().copied() {
        // CF.Mul sous pk1
        let ft1   = bd1.under_pk1.ft_by_pos.get(&pos)
            .expect("BD1 Ft(pk1) manquant pour une position commune");
        let ft1_p = bd2.under_pk1.ft_by_pos.get(&pos)
            .expect("BD2 Ft(pk1) manquant pour une position commune");
        out_pk1.push(
            cf_mul(ft1, ft1_p, &kp1.public_key).expect("cf_mul(pk1) a echoue")
        );

        // CF.Mul sous pk2
        let ft2   = bd1.under_pk2.ft_by_pos.get(&pos)
            .expect("BD1 Ft(pk2) manquant pour une position commune");
        let ft2_p = bd2.under_pk2.ft_by_pos.get(&pos)
            .expect("BD2 Ft(pk2) manquant pour une position commune");
        out_pk2.push(
            cf_mul(ft2, ft2_p, &kp2.public_key).expect("cf_mul(pk2) a echoue")
        );
    }

    println!(
        "  [Phase 3] termine en {:.3?} ({} CF.Mul x 2 cles).",
        t_start.elapsed(), out_pk1.len()
    );

    (out_pk1, out_pk2)
}

// ---------------------------------------------------------
// Phase 4 — BD : Dec2 sur chaque triplet + somme
// ---------------------------------------------------------

pub fn phase4_decrypt_and_count(label: &str, cts: &[CfSnd], kp: &KeyPair) -> usize {
    println!(
        "  [Phase 4] {} : Dec2 ({} triplets)...",
        label, cts.len()
    );
    let t_start = Instant::now();

    let mut sum = BigUint::from(0u32);
    for ct in cts {
        let m = cf_mul_dec(ct, &kp.public_key, &kp.secret_key)
            .expect("cf_mul_dec a echoue");
        sum += m;
    }

    let count = sum.to_u64_digits().last().copied().unwrap_or(0) as usize;

    println!(
        "  [Phase 4] {} : termine en {:.3?}  ->  cardinal = {}",
        label, t_start.elapsed(), count
    );

    count
}