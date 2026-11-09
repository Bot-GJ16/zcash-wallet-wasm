use rusqlite::{Connection, MAIN_DB};
#[cfg(target_arch = "wasm32")]
use rusqlite_browser as rusqlite;
use zcash_voting::{
    round::{RoundParams, VotingDb},
    session::{resume_plan, Decision},
    types::Network,
};

const ROUND_ID: &str = "0101010101010101010101010101010101010101010101010101010101010101";

fn round_params() -> RoundParams {
    RoundParams {
        vote_round_id: ROUND_ID.into(),
        snapshot_height: 1000,
        ea_pk: vec![0xEA; 32],
        nc_root: vec![0xAA; 32],
        nullifier_imt_root: vec![0xBB; 32],
    }
}

fn read_snapshot(bytes: &[u8]) -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.deserialize_read_exact(MAIN_DB, std::io::Cursor::new(bytes), bytes.len(), false)
        .unwrap();
    conn
}

fn legacy_bytes(sql: &str) -> Vec<u8> {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../fixtures/browser_v17.sql"))
        .unwrap();
    conn.execute_batch("PRAGMA user_version = 17; PRAGMA foreign_keys = OFF;")
        .unwrap();
    conn.execute_batch(sql).unwrap();
    conn.serialize(MAIN_DB).unwrap().to_vec()
}

fn assert_rejected(wallet: &str, network: Network, bytes: &[u8], expected: &str) {
    let error = match VotingDb::open_browser(wallet, network, Some(bytes)) {
        Ok(_) => panic!("database must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains(expected), "{error}");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn browser_db_round_trip_preserves_resume_plan_and_owns_bytes() {
    let db = VotingDb::open_browser("wallet-a", Network::Testnet, None).unwrap();
    db.create_round(Network::Testnet, &round_params(), Some("session-state"))
        .unwrap();
    db.set_ballot_intent(ROUND_ID, 1, Decision::Skipped, 3)
        .unwrap();
    let before = resume_plan(&db, ROUND_ID, &[1]).unwrap();
    let mut bytes = db.serialize_bytes().unwrap();
    let restored = VotingDb::open_browser("wallet-a", Network::Testnet, Some(&bytes)).unwrap();
    bytes.fill(0);
    drop(db);
    assert_eq!(resume_plan(&restored, ROUND_ID, &[1]).unwrap(), before);
    assert_eq!(
        restored.ballot_intents(ROUND_ID).unwrap(),
        vec![(1, Decision::Skipped)]
    );
    assert!(restored.list_rounds().unwrap()[0].created_at > 1_700_000_000);
    restored.clear_round(ROUND_ID).unwrap();
    let reopened = VotingDb::open_browser(
        "wallet-a",
        Network::Testnet,
        Some(&restored.serialize_bytes().unwrap()),
    )
    .unwrap();
    assert!(reopened.ballot_intents(ROUND_ID).unwrap().is_empty());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn browser_db_rejects_another_owner_and_network() {
    let db = VotingDb::open_browser("wallet-a", Network::Testnet, None).unwrap();
    assert!(db.scoped("wallet-b").is_err());
    assert!(db.scoped("wallet-a").is_ok());
    let bytes = db.serialize_bytes().unwrap();
    assert_rejected(
        "wallet-b",
        Network::Testnet,
        &bytes,
        "wallet owner mismatch",
    );
    assert_rejected("wallet-a", Network::Mainnet, &bytes, "network mismatch");
    assert_rejected("wallet-a", Network::Regtest, &bytes, "network mismatch");
    assert!(db
        .create_round(Network::Mainnet, &round_params(), None)
        .is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn browser_db_empty_input_and_metadata() {
    for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
        let db = VotingDb::open_browser("wallet-a", network, Some(&[])).unwrap();
        let conn = read_snapshot(&db.serialize_bytes().unwrap());
        let stored: (i64, String, String) = conn
            .query_row(
                "SELECT singleton, wallet_id, network FROM wallet_metadata",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            stored,
            (1, "wallet-a".into(), format!("{network:?}").to_lowercase())
        );
        assert_eq!(
            conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            25
        );
    }
    assert!(VotingDb::open_browser("", Network::Testnet, None).is_err());
    assert!(VotingDb::open_browser("wallet-a", Network::Testnet, Some(b"invalid sqlite")).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn browser_db_upgrades_v17_preserving_round_and_intent() {
    let bytes = legacy_bytes(&format!(
        "INSERT INTO rounds (round_id,wallet_id,network,snapshot_height,ea_pk,nc_root,nullifier_imt_root,phase,created_at)
         VALUES ('{ROUND_ID}','wallet-a','testnet',1000,X'EA',X'AA',X'BB',0,42);
         INSERT INTO ballot_intent VALUES ('{ROUND_ID}','wallet-a',1,1,NULL,42,42);"
    ));
    let db = VotingDb::open_browser("wallet-a", Network::Testnet, Some(&bytes)).unwrap();
    assert_eq!(db.list_rounds().unwrap()[0].created_at, 42);
    assert_eq!(
        db.ballot_intents(ROUND_ID).unwrap(),
        vec![(1, Decision::Skipped)]
    );
    assert_eq!(
        read_snapshot(&db.serialize_bytes().unwrap())
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        25
    );
    assert_rejected(
        "wallet-b",
        Network::Testnet,
        &bytes,
        "wallet owner mismatch",
    );
    assert_rejected("wallet-a", Network::Mainnet, &bytes, "network mismatch");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn browser_db_rejects_conflicting_legacy_cache_and_child_owners() {
    for (sql, expected) in [
        ("INSERT INTO pir_proof_cache VALUES ('wallet-b','testnet',X'01',X'02',X'03',0,X'04',0,0);", "wallet owner mismatch"),
        ("INSERT INTO pir_proof_cache VALUES ('wallet-a','mainnet',X'01',X'02',X'03',0,X'04',0,0);", "network mismatch"),
        ("INSERT INTO ballot_intent VALUES ('orphan','wallet-b',1,1,NULL,0,0);", "wallet owner mismatch"),
        ("INSERT INTO ballot_intent VALUES ('orphan','wallet-a',1,1,NULL,0,0); INSERT INTO ballot_intent VALUES ('orphan','wallet-b',1,1,NULL,0,0);", "wallet owner mismatch"),
    ] {
        assert_rejected("wallet-a", Network::Testnet, &legacy_bytes(sql), expected);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn browser_db_upgrade_preserves_helper_journal_and_cascades() {
    let bytes = legacy_bytes(&format!(
        r#"INSERT INTO rounds (round_id,wallet_id,network,snapshot_height,ea_pk,nc_root,nullifier_imt_root,phase,created_at)
         VALUES ('{ROUND_ID}','wallet-a','testnet',1000,X'EA',X'AA',X'BB',0,42);
         INSERT INTO bundles (round_id,wallet_id,bundle_index,van_comm_rand) VALUES ('{ROUND_ID}','wallet-a',0,X'ABCD');
         INSERT INTO votes (round_id,wallet_id,bundle_index,proposal_id,choice,created_at,commitment_bundle_json)
         VALUES ('{ROUND_ID}','wallet-a',0,1,1,42,'{{"vc_tree_position":null}}');
         INSERT INTO helper_share_plans VALUES ('{ROUND_ID}','wallet-a',0,1,'{{"vc_tree_position":null}}','[]','[]',1,'strict',42);
         INSERT INTO share_delegations (round_id,wallet_id,bundle_index,proposal_id,share_index,sent_to_urls,nullifier,created_at,ambiguous_urls,attempting_urls,target_count,submit_at)
         VALUES ('{ROUND_ID}','wallet-a',0,1,0,'["https://accepted.example"]',X'AB',42,'["https://unknown.example"]','["https://attempting.example"]',3,99);"#
    ));
    let db = VotingDb::open_browser("wallet-a", Network::Testnet, Some(&bytes)).unwrap();
    let conn = read_snapshot(&db.serialize_bytes().unwrap());
    let journal: (String, String, String, i64, i64) = conn.query_row(
        "SELECT sent_to_urls, ambiguous_urls, attempting_urls, target_count, submit_at FROM share_delegations", [],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).unwrap();
    assert_eq!(
        journal,
        (
            "[\"https://accepted.example\"]".into(),
            "[\"https://unknown.example\"]".into(),
            "[\"https://attempting.example\"]".into(),
            3,
            99
        )
    );
    assert_eq!(
        conn.query_row("SELECT van_comm_rand FROM bundles", [], |r| r
            .get::<_, Vec<u8>>(0))
            .unwrap(),
        vec![0xAB, 0xCD]
    );
    conn.execute("UPDATE votes SET commitment_bundle_json = '{\"vc_tree_position\":1}', vc_tree_position = 1", []).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT commitment_bundle_json FROM helper_share_plans",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "{\"vc_tree_position\":1}"
    );
    assert!(db.clear_round(ROUND_ID).is_err());
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn.execute("DELETE FROM rounds WHERE round_id=?1", [ROUND_ID])
        .unwrap();
    for table in [
        "helper_share_plans",
        "share_delegations",
        "votes",
        "bundles",
    ] {
        assert_eq!(
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
