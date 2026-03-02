// =========================================================
// src/bin/client.rs — Client PSI ExactMatch (BD1 ou BD2)
//
// Séparation  chiffrement / déchiffrement :
//
//   Phase 2 (chiffrement) :
//     - utilise &PublicKey (pk_self + pk_other reçue du serveur)
//     - la SecretKey n'est PAS nécessaire pour chiffrer
//     - pk_other est une vraie PublicKey Paillier
//
//   Phase 4 (déchiffrement) :
//     - utilise &KeyPair COMPLET (kp_self avec sk.lambda, sk.mu)
//     - la SecretKey ne quitte JAMAIS cette machine
//
// Flux Phase 0 (échange de clés via le serveur) :
//   0a) BD envoie pk_self au serveur
//   0b) BD reçoit pk_other relayée par le serveur
//   - Chaque BD connaît maintenant la vraie pk de l'autre
//   - phase2 peut chiffrer ses Ft sous n1 ET n2 corrects
// =========================================================

use std::env;
use std::net::{TcpListener, TcpStream};
use std::io;
use std::time::Instant;

use paillier_crypto::exactmatch::{
    load_nss_from_csv,
    phase0_keygen, phase1_build_table,
    phase2_prepare_dual_ft, phase4_decrypt_and_count,
    DualFtBundle, FtBundle,
};
use paillier_crypto::paillier::p_keygen::PublicKey;
use paillier_crypto::net_protocol::{
    BandwidthMeter,
    MsgPubKey, MsgDualBundle, MsgFtBundle, MsgTriplets,
    send_tracked, recv_tracked,
};

const SERVER_ADDR_BD1: &str = "127.0.0.1:7001";
const SERVER_ADDR_BD2: &str = "127.0.0.1:7002";
const LISTEN_PORT_BD1: u16  = 7003;
const LISTEN_PORT_BD2: u16  = 7004;

// ─────────────────────────────────────────────────────────
// Reconstruction d'une PublicKey depuis un message réseau
//
// CORRECT : on reconstruit uniquement PublicKey (n, g, n²).
// ─────────────────────────────────────────────────────────
fn pubkey_from_msg(msg: MsgPubKey) -> PublicKey {
    PublicKey {
        n:         msg.n,
        g:         msg.g,
        n_squared: msg.n_squared,
    }
}

// ─────────────────────────────────────────────────────────
// Sérialisation DualFtBundle -> message réseau
// ─────────────────────────────────────────────────────────
fn bundle_to_msg(b: &DualFtBundle) -> MsgDualBundle {
    MsgDualBundle {
        under_pk1: MsgFtBundle {
            entries: b.under_pk1.ft_by_pos.iter()
                .map(|(&pos, ft)| (pos, ft.clone()))
                .collect(),
        },
        under_pk2: MsgFtBundle {
            entries: b.under_pk2.ft_by_pos.iter()
                .map(|(&pos, ft)| (pos, ft.clone()))
                .collect(),
        },
    }
}

// ─────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────
fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let bd_id: u8 = args.iter()
        .position(|a| a == "--bd")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .expect("Usage : client --bd <1|2> --csv <fichier.csv>");
    let csv_path: &str = args.iter()
        .position(|a| a == "--csv")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .expect("Usage : client --bd <1|2> --csv <fichier.csv>");

    let label       = format!("BD{}", bd_id);
    let server_addr = if bd_id == 1 { SERVER_ADDR_BD1 } else { SERVER_ADDR_BD2 };
    let listen_port = if bd_id == 1 { LISTEN_PORT_BD1 } else { LISTEN_PORT_BD2 };

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║   CLIENT PSI — {}                                   ║", label);
    println!("╚══════════════════════════════════════════════════════╝\n");

    let mut meter = BandwidthMeter::new();
    let t_total   = Instant::now();

    // Chargement CSV
    let nss_list = load_nss_from_csv(csv_path);
    println!("[{}] {} NSS chargés depuis {}.", label, nss_list.len(), csv_path);

    // ── Phase 0a : génération de la clé Paillier locale ──────────────
    // kp_self contient pk (publique) + sk (SECRÈTE, ne quitte jamais cette machine)
    println!("\n[{}] Phase 0a : génération des clés Paillier...", label);
    let kp_self = phase0_keygen(&label, 1024);
    println!(
        "[{}] Clé générée : n = {} bits, sk reste locale.",
        label, kp_self.public_key.n.bits()
    );

    // Connexion au serveur
    println!("[{}] Connexion au serveur {}...", label, server_addr);
    let mut stream = loop {
        match TcpStream::connect(server_addr) {
            Ok(s)  => { println!("[{}] Connecté.", label); break s; }
            Err(_) => {
                eprint!(".");
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    };

    // ── Phase 0a : envoi de pk_self ───────────────────────────────────
    // On n'envoie QUE la clé publique (n, g, n²) — jamais sk.
    meter.begin("Phase 0a — envoi pk_self");
    let pk_payload = MsgPubKey {
        n:         kp_self.public_key.n.clone(),
        g:         kp_self.public_key.g.clone(),
        n_squared: kp_self.public_key.n_squared.clone(),
    }.encode();
    send_tracked(&mut stream, &pk_payload, &mut meter)?;
    meter.end();
    println!(
        "[{}] Phase 0a : pk_self envoyée ({} octets, sk NON envoyée).",
        label, pk_payload.len()
    );

    // ── Phase 0b : réception de pk_other (vraie clé de l'autre BD) ───
    // Le serveur a reçu pk1 et pk2, et les a croisées.
    // BD1 reçoit pk2 (la vraie clé publique de BD2).
    // BD2 reçoit pk1 (la vraie clé publique de BD1).
    meter.begin("Phase 0b — réception pk_other");
    let pk_other_buf = recv_tracked(&mut stream, &mut meter)?;
    meter.end();
    let pk_other: PublicKey = pubkey_from_msg(MsgPubKey::decode(&pk_other_buf)?);
    println!(
        "[{}] Phase 0b : pk_other reçue (n_other = {} bits).",
        label, pk_other.n.bits()
    );

    // Assignation (pk1, pk2) selon le rôle du BD
    // BD1 -> pk1 = kp_self.public_key, pk2 = pk_other
    // BD2 -> pk1 = pk_other,           pk2 = kp_self.public_key
    let (pk1, pk2): (&PublicKey, &PublicKey) = if bd_id == 1 {
        (&kp_self.public_key, &pk_other)
    } else {
        (&pk_other, &kp_self.public_key)
    };

    // ── Phase 1 : table creuse locale ────────────────────────────────
    println!("\n[{}] Phase 1 : construction de la table creuse...", label);
    let table = phase1_build_table(&label, &nss_list);

    // ── Phase 2 : préparation + envoi DualFtBundle ───────────────────
    // phase2_prepare_dual_ft prend &PublicKey — pas de KeyPair factice.
    // Les Ft sont chiffrés sous les vrais modules n1 et n2.
    println!("[{}] Phase 2 : préparation Ft sous pk1 (n={} bits) et pk2 (n={} bits)...",
        label, pk1.n.bits(), pk2.n.bits());
    let bundle = phase2_prepare_dual_ft(&label, &table, pk1, pk2);

    meter.begin("Phase 2 — envoi bundle");
    let bundle_payload = bundle_to_msg(&bundle).encode();
    send_tracked(&mut stream, &bundle_payload, &mut meter)?;
    meter.end();
    println!(
        "[{}] Phase 2 terminée — {:.1} Ko envoyés.",
        label, bundle_payload.len() as f64 / 1024.0
    );

    // ── Phase 3 : réception des triplets du serveur ──────────────────
    println!("\n[{}] Phase 3 : ouverture :{}...", label, listen_port);
    let listener = TcpListener::bind(format!("127.0.0.1:{}", listen_port))?;
    println!("[{}] En attente des triplets...", label);

    meter.begin("Phase 3 — réception triplets");
    let (mut ret_stream, _) = listener.accept()?;
    let buf = recv_tracked(&mut ret_stream, &mut meter)?;
    meter.end();

    let triplets = MsgTriplets::decode(&buf)?.triplets;
    println!(
        "[{}] Phase 3 terminée — {} triplets ({:.1} Ko).",
        label, triplets.len(), buf.len() as f64 / 1024.0
    );

    // ── Phase 4 : déchiffrement avec la clé secrète locale ───────────
    // kp_self est le seul KeyPair complet disponible sur cette machine.
    // sk.lambda et sk.mu n'ont jamais transité sur le réseau.
    println!("\n[{}] Phase 4 : déchiffrement Dec2 avec sk locale...", label);
    meter.begin("Phase 4 — déchiffrement");
    let cardinal = phase4_decrypt_and_count(&label, &triplets, &kp_self);
    meter.end();

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  {} — RÉSULTAT                                      ║", label);
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  |BD1 ^ BD2|  =  {}", cardinal);
    println!("║  Temps total  :  {:.3?}", t_total.elapsed());
    println!("╚══════════════════════════════════════════════════════╝");

    meter.report();
    Ok(())
}