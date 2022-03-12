    CREATE TABLE IF NOT EXISTS constants (
        key TEXT UNIQUE,
        value BYTEA
    );

    CREATE TABLE IF NOT EXISTS airdrop_scheduled (
        key TEXT UNIQUE,
        value BYTEA
    );

    CREATE TABLE IF NOT EXISTS OPERATOR_COST (
        id SERIAL PRIMARY KEY,
        hash char(64),
        cost bigint,
        used_gas bigint,
        sender char(40),
        to_address char(40) ,
        sig char(100),
        status varchar(100),
        reason varchar(100)
    );

    CREATE TABLE IF NOT EXISTS neon_accounts (
        neon_account CHAR(42),
        pda_account VARCHAR(50),
        code_account VARCHAR(50),
        slot BIGINT,
        code TEXT,

        UNIQUE(pda_account, code_account)
    );

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

        UNIQUE(sol_sign, neon_sign, idx),
        UNIQUE(neon_sign, sol_sign, idx)
    );

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

    CREATE TABLE IF NOT EXISTS transaction_receipts (
        slot        BIGINT,
        signature   VARCHAR(88),
        trx         BYTEA,
        PRIMARY KEY (slot, signature)
    );

    CREATE TABLE IF NOT EXISTS constants (
        key TEXT UNIQUE,
        value BYTEA
    )

    CREATE TABLE IF NOT EXISTS airdrop_scheduled (
        key TEXT UNIQUE,
        value BYTEA
    )

    CREATE TABLE IF NOT EXISTS transaction_receipts (
        slot        BIGINT,
        signature   VARCHAR(88),
        trx         BYTEA,
        PRIMARY KEY (slot, signature)
    );

    CREATE TABLE IF NOT EXISTS test_storage (
        slot        BIGINT,
        signature   VARCHAR(88),
        trx         BYTEA,
        PRIMARY KEY (slot, signature)
    );
