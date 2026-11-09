CREATE TABLE legacy_delegation_evidence (
    round_id TEXT NOT NULL,
    wallet_id TEXT NOT NULL,
    bundle_index INTEGER NOT NULL,
    tx_hash TEXT NOT NULL,
    PRIMARY KEY (round_id, wallet_id, bundle_index),
    FOREIGN KEY (round_id, wallet_id, bundle_index)
        REFERENCES bundles(round_id, wallet_id, bundle_index) ON DELETE CASCADE
);

CREATE TABLE legacy_vote_evidence (
    round_id TEXT NOT NULL,
    wallet_id TEXT NOT NULL,
    bundle_index INTEGER NOT NULL,
    proposal_id INTEGER NOT NULL,
    tx_hash TEXT NOT NULL,
    PRIMARY KEY (round_id, wallet_id, bundle_index, proposal_id),
    FOREIGN KEY (round_id, wallet_id, bundle_index, proposal_id)
        REFERENCES votes(round_id, wallet_id, bundle_index, proposal_id) ON DELETE CASCADE
);
