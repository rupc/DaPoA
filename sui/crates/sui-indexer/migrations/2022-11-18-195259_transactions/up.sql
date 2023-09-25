CREATE TABLE transactions (
    id BIGSERIAL PRIMARY KEY,
    transaction_digest VARCHAR(255) NOT NULL,
    sender VARCHAR(255) NOT NULL,
    checkpoint_sequence_number BIGINT NOT NULL,
    transaction_time TIMESTAMP,
    transaction_kinds TEXT[] NOT NULL,
    -- object related
    created TEXT[] NOT NULL,
    mutated TEXT[] NOT NULL,
    deleted TEXT[] NOT NULL,
    unwrapped TEXT[] NOT NULL,
    wrapped TEXT[] NOT NULL,
    -- gas object related
    gas_object_id VARCHAR(255) NOT NULL,
    gas_object_sequence BIGINT NOT NULL,
    gas_object_digest VARCHAR(255) NOT NULL,
    -- gas budget & cost related
    gas_budget BIGINT NOT NULL,
    total_gas_cost BIGINT NOT NULL,
    computation_cost BIGINT NOT NULL,
    storage_cost BIGINT NOT NULL,
    storage_rebate BIGINT NOT NULL,
    -- gas price from transaction data,
    -- not the reference gas price
    gas_price BIGINT NOT NULL,
    -- serialized transaction
    transaction_content TEXT NOT NULL,
    transaction_effects_content TEXT NOT NULL,
    confirmed_local_execution BOOLEAN,
    UNIQUE(transaction_digest) 
);

CREATE INDEX transactions_transaction_digest ON transactions (transaction_digest);
CREATE INDEX transactions_transaction_time ON transactions (transaction_time);
CREATE INDEX transactions_sender ON transactions (sender);
CREATE INDEX transactions_gas_object_id ON transactions (gas_object_id);
CREATE INDEX transactions_checkpoint_sequence_number ON transactions (checkpoint_sequence_number);
