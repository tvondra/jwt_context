-- discard keys possibly left from previous test run, reconnect
CREATE ROLE test_jwt_user;

-- generate new keypair
SELECT * FROM jwt_generate_keys('ES256') \gset
SELECT * FROM jwt_generate_secret('HS256') AS secret \gset

-- superuser can change the keys
SET jwt.pubkey = :'public_raw';
SET jwt.secret = :'secret';

-- superuser should see the public key just fine
SELECT (setting = :'public_raw') AS pubkey_matches FROM pg_settings WHERE NAME = 'jwt.pubkey';
SELECT (setting = :'secret') AS secret_matches FROM pg_settings WHERE NAME = 'jwt.secret';

-- switch to unprivileged user
SET ROLE TO test_jwt_user;

-- but the unprivileged user should see the public key just fine too (it's still set)
SELECT (setting = :'public_raw') AS pubkey_matches FROM pg_settings WHERE NAME = 'jwt.pubkey';

-- the secret key should be redacted, though
SELECT setting AS secret_matches FROM pg_settings WHERE NAME = 'jwt.secret';
SHOW jwt.secret;

-- this should fail, it's a PG_SUSET option
SET jwt.pubkey = :'public_raw';
SET jwt.secret = :'secret';

-- reset should fail too
RESET jwt.pubkey;
RESET jwt.secret;

-- reset the role back to superuser
RESET ROLE;

RESET jwt.pubkey;
RESET jwt.secret;

DROP ROLE test_jwt_user;
