// =========================================================
// src/bin/server.rs — Serveur PSI ExactMatch
//
//
// Flux complet :
//   Phase 0a : reçoit pk1 de BD1, pk2 de BD2
//   Phase 0b : renvoie pk2 à BD1 et pk1 à BD2 
//   Phase 2  : reçoit DualFtBundle de BD1 et BD2
// =========================================================

use std::net::{TcpListener, TcpStream};
use std::io;
use std::thread;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::collections::HashSet;

use num_traits::Zero;

use paillier_crypto::exactmatch::{
    SparseTable, DualFtBundle, FtBundle,
    phase3_server_compute, CfSnd,
};
use paillier_crypto::paillier::p_keygen::PublicKey;
use paillier_crypto::{KeyPair, SecretKey};
use paillier_crypto::net_protocol::{
    BandwidthMeter,
    MsgPubKey, MsgDualBundle, MsgTriplets,
    send_tracked, recv_tracked,
};

const PORT_BD1: u16 = 7001;
const PORT_BD2: u16 = 7002;

// ─────────────────────────────────────────────────────────
// Données reçues de chaque BD
// ─────────────────────────────────────────────────────────
struct BdData {
    pk:     Option<PublicKey>,
    stream: Option<TcpStream>,   // conservé pour Phase 0b
    bundle: Option<DualFtBundle>,
    table:  Option<SparseTable>,
}
impl BdData {
    fn new() -> Self { BdData { pk: None, stream: None, bundle: None, table: None } }
}

// ─────────────────────────────────────────────────────────
// Phase 0a : accepter une connexion et lire pk
// ─────────────────────────────────────────────────────────
fn recv_pk(
    mut stream: TcpStream,
    label:      &str,
    meter:      &mut BandwidthMeter,
) -> io::Result<(PublicKey, TcpStream)> {
    println!("[Serveur] {} connecté depuis {:?}", label, stream.peer_addr()?);
    meter.begin(&format!("Phase0a recv {}", label));
    let buf = recv_tracked(&mut stream, meter)?;
    meter.end();
    let msg = MsgPubKey::decode(&buf)?;
    let pk  = PublicKey { n: msg.n, g: msg.g, n_squared: msg.n_squared };
    println!("[Serveur] {} Phase 0a : pk reçue (|n|={} bits)", label, pk.n.bits());
    Ok((pk, stream))
}

// ─────────────────────────────────────────────────────────
// Phase 0b : renvoyer pk_other à chaque BD sur la même connexion
// ─────────────────────────────────────────────────────────
fn send_pk_other(
    stream:   &mut TcpStream,
    pk_other: &PublicKey,
    label:    &str,
    meter:    &mut BandwidthMeter,
) -> io::Result<()> {
    meter.begin(&format!("Phase0b send pk_other to {}", label));
    let payload = MsgPubKey {
        n:         pk_other.n.clone(),
        g:         pk_other.g.clone(),
        n_squared: pk_other.n_squared.clone(),
    }.encode();
    send_tracked(stream, &payload, meter)?;
    meter.end();
    println!("[Serveur] {} Phase 0b : pk_other relayée ({} octets)", label, payload.len());
    Ok(())
}

// ─────────────────────────────────────────────────────────
// Phase 2 : lire le DualFtBundle sur la connexion existante
// ─────────────────────────────────────────────────────────
fn recv_bundle(
    stream: &mut TcpStream,
    label:  &str,
    meter:  &mut BandwidthMeter,
) -> io::Result<DualFtBundle> {
    meter.begin(&format!("Phase2 recv {}", label));
    let buf = recv_tracked(stream, meter)?;
    meter.end();
    let dual_msg = MsgDualBundle::decode(&buf)?;
    let bundle = DualFtBundle {
        under_pk1: FtBundle { ft_by_pos: dual_msg.under_pk1.entries.into_iter().collect() },
        under_pk2: FtBundle { ft_by_pos: dual_msg.under_pk2.entries.into_iter().collect() },
    };
    println!(
        "[Serveur] {} Phase 2 : {} positions reçues",
        label, bundle.under_pk1.ft_by_pos.len()
    );
    Ok(bundle)
}

// ─────────────────────────────────────────────────────────
// Phase 3 : envoi des triplets vers un BD (connexion sortante)
// ─────────────────────────────────────────────────────────
fn send_triplets(
    mut stream: TcpStream,
    label:      &str,
    triplets:   &[CfSnd],
    meter:      &mut BandwidthMeter,
) -> io::Result<()> {
    meter.begin(&format!("Phase3 send {}", label));
    let payload = MsgTriplets { triplets: triplets.to_vec() }.encode();
    send_tracked(&mut stream, &payload, meter)?;
    meter.end();
    println!(
        "[Serveur] {} Phase 3 : {} triplets envoyés ({:.1} Ko)",
        label, triplets.len(), payload.len() as f64 / 1024.0
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────
fn main() -> io::Result<()> {
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║   SERVEUR PSI — Moteur de Calculs                    ║");
    println!("║   BD1→:7001  BD2→:7002  retour→:7003/:7004           ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    let meter1: Arc<Mutex<BandwidthMeter>> = Arc::new(Mutex::new(BandwidthMeter::new()));
    let meter2: Arc<Mutex<BandwidthMeter>> = Arc::new(Mutex::new(BandwidthMeter::new()));

    // ── Phase 0a : accepter BD1 et BD2 en parallèle ──────────────────
    let data1: Arc<Mutex<BdData>> = Arc::new(Mutex::new(BdData::new()));
    let data2: Arc<Mutex<BdData>> = Arc::new(Mutex::new(BdData::new()));

    let listener1 = TcpListener::bind(format!("127.0.0.1:{}", PORT_BD1))?;
    println!("[Serveur] En attente de BD1 sur :{}...", PORT_BD1);
    let (d1, m1) = (Arc::clone(&data1), Arc::clone(&meter1));
    let t1 = thread::spawn(move || {
        let (stream, _) = listener1.accept().expect("accept BD1 échoué");
        let (pk, s) = recv_pk(stream, "BD1", &mut m1.lock().unwrap())
            .expect("recv_pk BD1 échoué");
        let mut d = d1.lock().unwrap();
        d.pk     = Some(pk);
        d.stream = Some(s);
    });

    let listener2 = TcpListener::bind(format!("127.0.0.1:{}", PORT_BD2))?;
    println!("[Serveur] En attente de BD2 sur :{}...", PORT_BD2);
    let (d2, m2) = (Arc::clone(&data2), Arc::clone(&meter2));
    let t2 = thread::spawn(move || {
        let (stream, _) = listener2.accept().expect("accept BD2 échoué");
        let (pk, s) = recv_pk(stream, "BD2", &mut m2.lock().unwrap())
            .expect("recv_pk BD2 échoué");
        let mut d = d2.lock().unwrap();
        d.pk     = Some(pk);
        d.stream = Some(s);
    });

    t1.join().expect("thread Phase0a BD1 panique");
    t2.join().expect("thread Phase0a BD2 panique");
    println!("\n[Serveur] Phase 0a terminée — pk1 et pk2 reçues.");

    // ── Phase 0b : échange croisé des pk ─────────────────────────────
    // Envoyer pk2 à BD1 et pk1 à BD2 sur les connexions existantes.
    {
        let pk1 = data1.lock().unwrap().pk.clone().unwrap();
        let pk2 = data2.lock().unwrap().pk.clone().unwrap();

        let (d1b, m1b) = (Arc::clone(&data1), Arc::clone(&meter1));
        let (d2b, m2b) = (Arc::clone(&data2), Arc::clone(&meter2));
        let pk2_for_bd1 = pk2.clone();
        let pk1_for_bd2 = pk1.clone();

        let tb1 = thread::spawn(move || {
            let mut d = d1b.lock().unwrap();
            let stream = d.stream.as_mut().expect("stream BD1 manquant");
            send_pk_other(stream, &pk2_for_bd1, "BD1", &mut m1b.lock().unwrap())
                .expect("send pk_other à BD1 échoué");
        });
        let tb2 = thread::spawn(move || {
            let mut d = d2b.lock().unwrap();
            let stream = d.stream.as_mut().expect("stream BD2 manquant");
            send_pk_other(stream, &pk1_for_bd2, "BD2", &mut m2b.lock().unwrap())
                .expect("send pk_other à BD2 échoué");
        });
        tb1.join().expect("thread Phase0b BD1 panique");
        tb2.join().expect("thread Phase0b BD2 panique");
    }
    println!("[Serveur] Phase 0b terminée — pk croisées envoyées.");

    // ── Phase 2 : réception des DualFtBundles ────────────────────────
    println!("[Serveur] Phase 2 : réception des bundles...");
    {
        let (d1c, m1c) = (Arc::clone(&data1), Arc::clone(&meter1));
        let (d2c, m2c) = (Arc::clone(&data2), Arc::clone(&meter2));

        let tc1 = thread::spawn(move || {
            let mut d = d1c.lock().unwrap();
            let stream = d.stream.as_mut().expect("stream BD1 manquant");
            let bundle = recv_bundle(stream, "BD1", &mut m1c.lock().unwrap())
                .expect("recv_bundle BD1 échoué");
            let positions: HashSet<usize> = bundle.under_pk1.ft_by_pos.keys().copied().collect();
            d.table  = Some(SparseTable { active: positions });
            d.bundle = Some(bundle);
        });
        let tc2 = thread::spawn(move || {
            let mut d = d2c.lock().unwrap();
            let stream = d.stream.as_mut().expect("stream BD2 manquant");
            let bundle = recv_bundle(stream, "BD2", &mut m2c.lock().unwrap())
                .expect("recv_bundle BD2 échoué");
            let positions: HashSet<usize> = bundle.under_pk1.ft_by_pos.keys().copied().collect();
            d.table  = Some(SparseTable { active: positions });
            d.bundle = Some(bundle);
        });
        tc1.join().expect("thread Phase2 BD1 panique");
        tc2.join().expect("thread Phase2 BD2 panique");
    }
    println!("[Serveur] Phase 2 terminée.");

    // ── Phase 3 : CF.Mul ─────────────────────────────────────────────
    println!("[Serveur] Phase 3 : CF.Mul...");
    let t_p3 = Instant::now();
    let (agg1, agg2) = {
        let d1 = data1.lock().unwrap();
        let d2 = data2.lock().unwrap();
        let dummy_sk = SecretKey {
            lambda: num_bigint::BigUint::zero(),
            mu:     num_bigint::BigUint::zero(),
        };
        let kp1 = KeyPair {
            public_key: d1.pk.clone().expect("pk1 manquante"),
            secret_key: dummy_sk.clone(),
        };
        let kp2 = KeyPair {
            public_key: d2.pk.clone().expect("pk2 manquante"),
            secret_key: dummy_sk,
        };
        phase3_server_compute(
            d1.table.as_ref().expect("table1 manquante"),
            d2.table.as_ref().expect("table2 manquante"),
            d1.bundle.as_ref().expect("bundle1 manquant"),
            d2.bundle.as_ref().expect("bundle2 manquant"),
            &kp1, &kp2,
        )
    };
    println!(
        "[Serveur] Phase 3 en {:.3?} — {} triplets pk1, {} triplets pk2",
        t_p3.elapsed(), agg1.len(), agg2.len()
    );

    // ── Phase 3 : envoi des résultats ─────────────────────────────────
    println!("[Serveur] Envoi → BD1:7003 | BD2:7004...");
    let agg1: Arc<Vec<CfSnd>> = Arc::new(agg1);
    let agg2: Arc<Vec<CfSnd>> = Arc::new(agg2);
    let m1d: Arc<Mutex<BandwidthMeter>> = Arc::clone(&meter1);
    let m2d: Arc<Mutex<BandwidthMeter>> = Arc::clone(&meter2);

    let a1 = Arc::clone(&agg1);
    let ts1 = thread::spawn(move || {
        loop {
            match TcpStream::connect("127.0.0.1:7003") {
                Ok(s) => {
                    send_triplets(s, "BD1", &a1, &mut m1d.lock().unwrap())
                        .expect("envoi BD1 échoué");
                    break;
                }
                Err(_) => thread::sleep(std::time::Duration::from_millis(100)),
            }
        }
    });
    let a2 = Arc::clone(&agg2);
    let ts2 = thread::spawn(move || {
        loop {
            match TcpStream::connect("127.0.0.1:7004") {
                Ok(s) => {
                    send_triplets(s, "BD2", &a2, &mut m2d.lock().unwrap())
                        .expect("envoi BD2 échoué");
                    break;
                }
                Err(_) => thread::sleep(std::time::Duration::from_millis(100)),
            }
        }
    });
    ts1.join().expect("thread send BD1 panique");
    ts2.join().expect("thread send BD2 panique");

    println!("\n[Serveur] ─── Rapport BD1 ↔ Serveur ───");
    meter1.lock().unwrap().report();
    println!("[Serveur] ─── Rapport BD2 ↔ Serveur ───");
    meter2.lock().unwrap().report();

    Ok(())
}