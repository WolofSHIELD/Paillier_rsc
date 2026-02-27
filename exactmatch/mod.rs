pub use num_bigint::BigUint;
pub use num_bigint::RandBigInt;
pub use rand_core::OsRng;
pub use std::collections::{HashMap, HashSet};

// ── Types ─────────────────────────────────────────────────

// CF Première Forme
pub use exactmatch::CfFst;

// CF Seconde Forme (triplet)
pub use exactmatch::CfSnd;

// Table creuse
pub use exactmatch::SparseTable;

// Nouveau bundle préparé pour le serveur
pub use exactmatch::FtBundle;
pub use exactmatch::DualFtBundle;

// ── Constantes ────────────────────────────────────────────
pub use exactmatch::HASH_BITS;
pub use exactmatch::TABLE_SIZE;

// ── Fonctions ─────────────────────────────────────────────

// Hash + parsing
pub use exactmatch::simple_hash;
pub use exactmatch::load_nss_from_csv;

// Phases protocole
pub use exactmatch::phase0_keygen;
pub use exactmatch::phase1_build_table;

// ⚠️ Nouveau nom (remplace phase2_generate_masks)
pub use exactmatch::phase2_prepare_dual_ft;

// Phase 3 (retourne maintenant Vec<CfSnd>, Vec<CfSnd>)
pub use exactmatch::phase3_server_compute;

// Phase 4 (décryptage Dec2 + somme)
pub use exactmatch::phase4_decrypt_and_count;