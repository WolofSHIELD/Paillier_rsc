// =========================================================
// ExactMatch — Implémentation corrigée et cohérente
// PSI (cardinal d’intersection) via Catalano–Fiore (1 niveau de Mul)
// Version “propre CF”:
//   - CF.Add : forme 1 (c0,c1)
//   - CF.Mul : forme 1 x forme 1 -> forme 2 (c0'',c1'',c2'')
//   - Déchiffrement final : Dec2 sur chaque triplet, puis somme.
//
// Points clés corrigés vs ton code précédent :
//   ✅ (K1) Hash sur 30 bits, table creuse (positions actives).
//   ✅ (K2) Le serveur NE DOIT PAS avoir les masques en clair.
//          Donc on ne passe plus `masks_clear` au serveur.
//          Chaque BD prépare directement Ft=(c0,c1) pour m=1.
//   ✅ (K3) Les modules n1 et n2 sont différents : on ne peut pas réutiliser
//          un même masque b pour pk1 et pk2. On génère des masques distincts
//          dans Z_{n1} et Z_{n2}.
//   ✅ (K4) Le serveur ne “relinéarise” pas en forme 1 : il garde les triplets.
//   ✅ (K5) Phase 4 : déchiffrement via cf_mul_dec (Dec2) + somme.
//
// Remarque sécurité : si le serveur reçoit t et t' (positions actives),
// il peut déjà dériver l’intersection AU NIVEAU DES POSITIONS HASHÉES.
// L’agrégation par un seul chiffré n’est pas réalisable “proprement” avec CF
// après multiplication (c’est la limitation CF). La solution correcte est
// d’envoyer une liste de triplets (sans les indices), idéalement mélangée.
// =========================================================

use num_bigint::{BigUint, RandBigInt};
use rand_core::OsRng;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

// --- Tes primitives (inchangées) ---
use crate::fiore_catalano::cf_mul::cf_mul::cf_mul;                  // CF.Mul (fst->snd)
use crate::fiore_catalano::cf_mul_dec::cf_mul_dec::cf_mul_dec;      // CF.Dec2 (snd)
use crate::paillier::p_encrypt::p_encrypt::p_encrypt;               // Paillier Enc
use crate::paillier::p_keygen::p_keygen::p_keygen;                  // Keygen
use crate::paillier::p_keygen::p_keygen::KeyPair;                   // KeyPair

// ─────────────────────────────────────────────────────────
// Constantes — HASH_BITS = 30
// ─────────────────────────────────────────────────────────

pub const HASH_BITS: usize = 30;
pub const TABLE_SIZE: usize = 1 << HASH_BITS; // 2^30

// ─────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────

/// CF Première Forme : (c0, c1)
/// où c0 = [m - b] mod n (clair) et c1 = P.Enc(b) mod n^2
pub type CfFst = (BigUint, BigUint);

/// CF Seconde Forme : (c0'', c1'', c2'')
pub type CfSnd = (BigUint, BigUint, BigUint);

/// Table creuse: ensemble des positions actives
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

    /// Positions communes entre deux tables (itère sur la plus petite)
    pub fn common_positions(&self, other: &SparseTable) -> Vec<usize> {
        let (small, big) = if self.active.len() <= other.active.len() {
            (&self.active, &other.active)
        } else {
            (&other.active, &self.active)
        };
        let mut res = Vec::with_capacity(small.len());
        for &pos in small.iter() {
            if big.contains(&pos) {
                res.push(pos);
            }
        }
        res
    }
}

/// Bundle de masques PREPARES pour le serveur, pour un module n donné.
/// Ici on stocke directement Ft=(c0,c1) pour m=1 aux positions actives.
/// Le serveur n’a PAS besoin des masques en clair.
pub struct FtBundle {
    pub ft_by_pos: HashMap<usize, CfFst>, // position -> (c0,c1)
}

/// Chaque BD prépare DEUX bundles :
///  - un bundle pour pk1 (mod n1)
///  - un bundle pour pk2 (mod n2)
/// car n1 != n2 en général.
pub struct DualFtBundle {
    pub under_pk1: FtBundle,
    pub under_pk2: FtBundle,
}

// ─────────────────────────────────────────────────────────
// Hash (à remplacer par SHA/BLAKE3 si besoin)
// ─────────────────────────────────────────────────────────

pub fn simple_hash(s: &str) -> usize {
    let mut h: u32 = 0;
    for ch in s.chars() {
        h = h.wrapping_shl(7).wrapping_sub(h).wrapping_add(ch as u32);
    }
    (h as usize) & (TABLE_SIZE - 1)
}

// ─────────────────────────────────────────────────────────
// CSV: colonne "NSS"
// ─────────────────────────────────────────────────────────

pub fn load_nss_from_csv(path: &str) -> Vec<String> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(path).unwrap_or_else(|e| panic!("Impossible d'ouvrir {} : {}", path, e));
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

// ─────────────────────────────────────────────────────────
// Phase 0 — KeyGen
// ─────────────────────────────────────────────────────────

pub fn phase0_keygen(label: &str, bits: u64) -> KeyPair {
    println!("  [Phase 0] {} : génération des clés ({} bits)...", label, bits);
    let t = Instant::now();
    let kp = p_keygen(bits).expect("p_keygen a échoué");
    println!("  [Phase 0] {} : clés générées en {:.3?}", label, t.elapsed());
    kp
}

// ─────────────────────────────────────────────────────────
// Phase 1 — Table creuse
// ─────────────────────────────────────────────────────────

pub fn phase1_build_table(label: &str, nss_list: &[String]) -> SparseTable {
    println!(
        "  [Phase 1] {} : construction table creuse ({} NSS, TABLE_SIZE=2^{})...",
        label,
        nss_list.len(),
        HASH_BITS
    );
    let table = SparseTable::build(nss_list);
    println!(
        "  [Phase 1] {} : {} position(s) active(s) — t[i]=1.",
        label,
        table.len()
    );
    table
}

// ─────────────────────────────────────────────────────────
// Helper: construire Ft=(c0,c1) pour m=1 sans exposer b au serveur
// Ft = ([1 - b] mod n, Enc(b))
// ─────────────────────────────────────────────────────────

fn make_ft_for_one(mask_b: &BigUint, kp: &KeyPair) -> CfFst {
    // c0 = (1 - b) mod n  => (1 + n - (b mod n)) mod n
    let n = &kp.public_key.n;
    let one = BigUint::from(1u32);
    let b_mod = mask_b % n;
    let c0 = (one + n - b_mod) % n;

    let c1 = p_encrypt(mask_b, &kp.public_key).expect("p_encrypt(b) a échoué");
    (c0, c1)
}

// ─────────────────────────────────────────────────────────
// Phase 2 — Préparation des Ft pour le serveur
//
// IMPORTANT: on génère des masques DIFFERENTS sous n1 et sous n2.
// Pourquoi ? parce que n1 != n2 et les masques vivent dans Z_n.
// ─────────────────────────────────────────────────────────

pub fn phase2_prepare_dual_ft(
    label: &str,
    table: &SparseTable,
    kp1: &KeyPair, // pk1 (module n1)
    kp2: &KeyPair, // pk2 (module n2)
) -> DualFtBundle {
    println!(
        "  [Phase 2] {} : préparation Ft (m=1) pour {} positions actives (sous pk1 et pk2)...",
        label,
        table.len()
    );

    let mut rng = OsRng;

    let mut ft_pk1: HashMap<usize, CfFst> = HashMap::with_capacity(table.len());
    let mut ft_pk2: HashMap<usize, CfFst> = HashMap::with_capacity(table.len());

    for &pos in table.active.iter() {
        // masque pour pk1 : b^(1)_pos ∈ Z_{n1}
        let b1 = rng.gen_biguint_below(&kp1.public_key.n);
        ft_pk1.insert(pos, make_ft_for_one(&b1, kp1));

        // masque pour pk2 : b^(2)_pos ∈ Z_{n2}
        let b2 = rng.gen_biguint_below(&kp2.public_key.n);
        ft_pk2.insert(pos, make_ft_for_one(&b2, kp2));
    }

    println!(
        "  [Phase 2] {} : Ft prêts. (Le serveur ne reçoit que (c0,c1), jamais b en clair.)",
        label
    );

    DualFtBundle {
        under_pk1: FtBundle { ft_by_pos: ft_pk1 },
        under_pk2: FtBundle { ft_by_pos: ft_pk2 },
    }
}

// ─────────────────────────────────────────────────────────
// Phase 3 — Serveur: CF.Mul sur positions communes + renvoi des triplets
//
// Le serveur connaît t et t' (positions actives). Il calcule donc `common`.
// Pour chaque pos commune, il récupère Ft_BD1(pos) et Ft_BD2(pos)
// sous pk1 -> cf_mul -> triplet sous pk1
// et sous pk2 -> cf_mul -> triplet sous pk2.
//
// IMPORTANT: on ne renvoie PAS les indices, seulement les triplets.
// Recommandé: mélanger (shuffle) la liste avant envoi.
// ─────────────────────────────────────────────────────────

pub fn phase3_server_compute(
    table1: &SparseTable,
    table2: &SparseTable,
    bd1: &DualFtBundle,
    bd2: &DualFtBundle,
    kp1: &KeyPair,
    kp2: &KeyPair,
) -> (Vec<CfSnd>, Vec<CfSnd>) {
    println!("  [Phase 3] Serveur : CF.Mul sur positions communes...");
    let t_start = Instant::now();

    let common = table1.common_positions(table2);
    println!("  [Phase 3] Serveur : {} position(s) commune(s).", common.len());

    let mut out_pk1: Vec<CfSnd> = Vec::with_capacity(common.len());
    let mut out_pk2: Vec<CfSnd> = Vec::with_capacity(common.len());

    for pos in common.iter().copied() {
        // Sous pk1
        let ft1 = bd1
            .under_pk1
            .ft_by_pos
            .get(&pos)
            .expect("BD1 Ft(pk1) manquant pour une pos commune");
        let ft1p = bd2
            .under_pk1
            .ft_by_pos
            .get(&pos)
            .expect("BD2 Ft(pk1) manquant pour une pos commune");
        let sf1 = cf_mul(ft1, ft1p, &kp1.public_key).expect("cf_mul(pk1) a échoué");
        out_pk1.push(sf1);

        // Sous pk2
        let ft2 = bd1
            .under_pk2
            .ft_by_pos
            .get(&pos)
            .expect("BD1 Ft(pk2) manquant pour une pos commune");
        let ft2p = bd2
            .under_pk2
            .ft_by_pos
            .get(&pos)
            .expect("BD2 Ft(pk2) manquant pour une pos commune");
        let sf2 = cf_mul(ft2, ft2p, &kp2.public_key).expect("cf_mul(pk2) a échoué");
        out_pk2.push(sf2);
    }

    // Optionnel (mais recommandé): mélanger l’ordre pour ne pas “indexer”
    // l’information côté BD (même si elle n’a pas les indices).
    // use rand::seq::SliceRandom;
    // let mut rng = rand::thread_rng();
    // out_pk1.shuffle(&mut rng);
    // out_pk2.shuffle(&mut rng);

    println!(
        "  [Phase 3] Serveur : terminé en {:.3?} ({} CF.Mul).",
        t_start.elapsed(),
        out_pk1.len()
    );

    (out_pk1, out_pk2)
}

// ─────────────────────────────────────────────────────────
// Phase 4 — BD: déchiffrement Dec2 sur chaque triplet + somme
//
// Chaque Dec2 retourne mm' = t[i]*t'[i] ∈ {0,1} pour une position.
// On somme => cardinal.
// ─────────────────────────────────────────────────────────

pub fn phase4_decrypt_and_count(label: &str, cts: &[CfSnd], kp: &KeyPair) -> usize {
    println!(
        "  [Phase 4] {} : déchiffrement Dec2 ({} triplets) + somme...",
        label,
        cts.len()
    );
    let t_start = Instant::now();

    let mut sum = BigUint::from(0u32);

    for ct in cts {
        let m = cf_mul_dec(ct, &kp.public_key, &kp.secret_key).expect("cf_mul_dec a échoué");
        // m devrait être 0/1 par construction.
        sum += m;
    }

    let count = sum.to_u64_digits().last().copied().unwrap_or(0) as usize;

    println!(
        "  [Phase 4] {} : terminé en {:.3?} -> cardinal déchiffré = {}",
        label,
        t_start.elapsed(),
        count
    );
    count
}