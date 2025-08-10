-- discard keys possibly left from previous test run, reconnect
ALTER DATABASE :DBNAME RESET ALL;
\connect

-- generate two secrets
SELECT * FROM jwt_generate_secret('HS256') AS secret \gset
SELECT * FROM jwt_generate_secret('HS256') AS secret2 \gset

-- generate an invalid signed context, with incorrect header (algorithm mismatch)
SELECT jwt_sign('HS256', :'secret', '{"alg": "ES256"}', '{"id": 123456, "exp": 123456789}') AS context \gset

-- the header says ES256, so the key is used as private key
SELECT jwt_verify(:'secret', :'context');

-- generate a valid signed context
SELECT jwt_sign('HS256', :'secret', '{"alg": "HS256"}', '{"id": 123456, "exp": 123456789}') AS context \gset

-- can't verify using a different secret
SELECT jwt_verify(:'secret2', :'context');

-- verify the signature with the right secret
SELECT jwt_verify(:'secret', :'context');

-- try to set it without the secret key set
SET jwt.context = :'context';

-- set the key for the database, reconnect
ALTER DATABASE :DBNAME SET jwt.secret = :'secret';
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
