    CREATE TABLE IF NOT EXISTS constants (
        key TEXT UNIQUE,
        value BYTEA
    );

    CREATE TABLE IF NOT EXISTS airdrop_scheduled (
        key TEXT UNIQUE,
        value BYTEA
    );

    CREATE TABLE IF NOT EXISTS neon_accounts (
        neon_address CHAR(42),
        pda_address VARCHAR(50),
        code_address VARCHAR(50),
        slot BIGINT,
        code TEXT,
        sol_sign CHAR(88)
    );
    ALTER TABLE neon_accounts ADD COLUMN IF NOT EXISTS neon_address CHAR(42);
    ALTER TABLE neon_accounts ADD COLUMN IF NOT EXISTS pda_address VARCHAR(50);
    ALTER TABLE neon_accounts ADD COLUMN IF NOT EXISTS code_address VARCHAR(50);
    ALTER TABLE neon_accounts ADD COLUMN IF NOT EXISTS sol_sign CHAR(88);
    CREATE UNIQUE INDEX IF NOT EXISTS neon_accounts_pda_address_code_address_key ON neon_accounts (pda_address, code_address);
    CREATE INDEX IF NOT EXISTS neon_accounts_neon_address_idx ON neon_accounts (neon_address);

    CREATE TABLE IF NOT EXISTS failed_airdrop_attempts (
        attempt_time    BIGINT,
        eth_address     TEXT,
        reason          TEXT
    );
    CREATE INDEX IF NOT EXISTS failed_attempt_time_idx ON failed_airdrop_attempts (attempt_time);

    CREATE TABLE IF NOT EXISTS airdrop_ready (
        eth_address     TEXT UNIQUE,
        scheduled_ts    BIGINT,
        finished_ts     BIGINT,
        duration        INTEGER,
        amount_galans   INTEGER
    );

    CREATE TABLE IF NOT EXISTS solana_block (
        slot BIGINT,
        hash CHAR(66),

        parent_hash CHAR(66),
        blocktime BIGINT,
        signatures BYTEA,

        UNIQUE(slot),
        UNIQUE(hash)
    );

    CREATE TABLE IF NOT EXISTS neon_transaction_logs (
        address CHAR(42),
        blockHash CHAR(66),
        blockNumber BIGINT,

        transactionHash CHAR(66),
        transactionLogIndex INT,
        topic TEXT,

        json TEXT,

        UNIQUE(blockNumber, transactionHash, transactionLogIndex)
    );
    CREATE INDEX IF NOT EXISTS neon_transaction_logs_block_hash ON neon_transaction_logs(blockHash);
    CREATE INDEX IF NOT EXISTS neon_transaction_logs_address ON neon_transaction_logs(address);
    CREATE INDEX IF NOT EXISTS neon_transaction_logs_topic ON neon_transaction_logs(topic);

    CREATE TABLE IF NOT EXISTS solana_neon_transactions (
        sol_sign CHAR(88),
        neon_sign CHAR(66),
        slot BIGINT,
        idx INT,
        neon_steps INT,

        UNIQUE(sol_sign, neon_sign, idx),
        UNIQUE(neon_sign, sol_sign, idx)
    );

    ALTER TABLE solana_neon_transactions ADD COLUMN IF NOT EXISTS neon_steps INT DEFAULT 0;

    CREATE TABLE IF NOT EXISTS neon_transactions (
        neon_sign CHAR(66),
        from_addr CHAR(42),
        sol_sign CHAR(88),
        slot BIGINT,
        block_hash CHAR(66),
        idx INT,

        nonce VARCHAR,
        gas_price VARCHAR,
        gas_limit VARCHAR,
        value VARCHAR,
        gas_used VARCHAR,

        to_addr CHAR(42),
        contract CHAR(42),

        status CHAR(3),

        return_value TEXT,

        v TEXT,
        r TEXT,
        s TEXT,

        calldata TEXT,
        logs BYTEA,

        UNIQUE(neon_sign),
        UNIQUE(sol_sign, idx)
    );

    ALTER TABLE neon_transactions ADD COLUMN IF NOT EXISTS tx_idx INT DEFAULT 0;

    CREATE TABLE IF NOT EXISTS solana_neon_transactions_costs (
        sol_sign CHAR(88) UNIQUE,
        operator VARCHAR(50),

        heap_size INT,
        bpf_instructions INT,

        sol_cost BIGINT,
        neon_income BIGINT
    );

    CREATE TABLE IF NOT EXISTS solana_transaction_receipts (
        slot        BIGINT,
        tx_idx      INT,
        signature   VARCHAR(88),
        tx          BYTEA,
        PRIMARY KEY (slot, signature)
    );

    CREATE TABLE IF NOT EXISTS test_storage (
        slot        BIGINT,
        tx_idx      INT,
        signature   VARCHAR(88),
        tx          BYTEA,
        PRIMARY KEY (slot, signature)
    );
