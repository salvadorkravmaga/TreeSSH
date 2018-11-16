CREATE TABLE IF NOT EXISTS accounts (
        identifier text NOT NULL,
	private_key_hex text NOT NULL,
	public_key_hex text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS fake_account (
	fakeidentifier text NOT NULL,
	fake_private_key_hex text NOT NULL,
	fake_public_key_hex text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS fakeAccounts (
	identifier text NOT NULL,
	EncryptionKey text NOT NULL,
	time_generated text NOT NULL,
	hash text DEFAULT 'None',
	proof_of_work text DEFAULT 'None',
	proof_of_work_time text DEFAULT '0'
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS keys (
	identifier text NOT NULL,
        public_key text NOT NULL,
	private_key text NOT NULL,
	time_generated text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS users (
	identifier text NOT NULL,
        EncryptionKey text NOT NULL,
	NewEncryptionKey text NOT NULL,
	time_generated text NOT NULL,
	encryption text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS peers (
        peer text NOT NULL,
	identifier text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS test_peers (
        peer text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS commands (
	sender text NOT NULL,
	unique_id text NOT NULL,
	response text DEFAULT 'None',
	time_queried text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS now_connected (
	connected_to text NOT NULL,
	command_line text DEFAULT 'None',
	time_connected text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS connected_to_us (
	user_connected text NOT NULL,
	time_connected text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS users_allowed (
	user_allowed text NOT NULL
);

NEW_TABLE

CREATE TABLE IF NOT EXISTS downloads (
	sender text NOT NULL,
	filename text NOT NULL,
	unique_id text NOT NULL
);
