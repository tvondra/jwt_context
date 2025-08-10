-- discard keys possibly left from previous test run, reconnect
ALTER DATABASE :DBNAME RESET ALL;
\connect

-- generate new keypair
SELECT * FROM jwt_generate_keys('ES256') \gset

-- generate an invalid signed context, with incorrect header (algorithm mismatch)
SELECT jwt_sign('ES256', :'private_raw', '{"alg": "HS256"}', '{"id": 123456, "exp": 123456789}') AS context \gset

-- the header says HS256, so the key is used as symmetric key
SELECT jwt_verify(:'public_raw', :'context');

-- generate a valid signed context
SELECT jwt_sign('ES256', :'private_raw', '{"alg": "ES256"}', '{"id": 123456, "exp": 123456789}') AS context \gset

-- can't verify using the private key
SELECT jwt_verify(:'private_raw', :'context');

-- verify the signature
SELECT jwt_verify(:'public_raw', :'context');

-- try to set it without the public key installed
SET jwt.context = :'context';

-- set the key for the database, reconnect
ALTER DATABASE :DBNAME SET jwt.pubkey = :'public_raw';
\connect

-- verify the context (function call forces loading the library, which
-- is what sets the check/assign hooks we need)
SELECT jwt_verify(NULL, :'context');

-- some bogus contexts first
SET jwt.context = 'blahblah';
SET jwt.context = 'foo:bar';
SET jwt.context = 'foo:bar:baz';

SHOW jwt.context;

-- now the correctly signed context
SET jwt.context = :'context';

SHOW jwt.context;

-- whole context
SELECT jwt();

-- existing key
SELECT jwt('id');

-- missing key
SELECT jwt('xid');
