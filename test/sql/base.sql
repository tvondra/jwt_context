\set ECHO none

-- disable the notices for the create script (shell types etc.)
SET client_min_messages = 'WARNING';
\i sql/jwt_context--1.0.0.sql
SET client_min_messages = 'NOTICE';

\set ECHO all

-- generate new keypair
SELECT * FROM jwt_generate_keys('ES256') \gset

-- generate new secret
SELECT * FROM jwt_generate_secret('HS256') \gset

-- incorrect combinations
SELECT * FROM jwt_generate_keys('HS256') \gset
SELECT * FROM jwt_generate_secret('ES256') \gset

SELECT jwt_sign(NULL, NULL, NULL, NULL);
SELECT jwt_verify(NULL, NULL);

SELECT jwt();
SELECT jwt('id');
SELECT jwt(NULL);
