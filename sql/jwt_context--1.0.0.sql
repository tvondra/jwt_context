/* jwt_context */
CREATE OR REPLACE FUNCTION jwt()
    RETURNS jsonb
    AS 'jwt_context', 'jwt_get'
    LANGUAGE C STABLE;

CREATE OR REPLACE FUNCTION jwt(key text)
    RETURNS text
    AS 'jwt_context', 'jwt_get_key'
    LANGUAGE C STABLE STRICT;

CREATE OR REPLACE FUNCTION jwt_sign(algo text, secret text, header json, body json)
    RETURNS text
    AS 'jwt_context', 'jwt_sign'
    LANGUAGE C STABLE STRICT;

CREATE OR REPLACE FUNCTION jwt_verify(secret text, context text)
    RETURNS bool
    AS 'jwt_context', 'jwt_verify'
    LANGUAGE C STABLE;

CREATE OR REPLACE FUNCTION jwt_generate_keys(algo text, private_raw out text, private_pem out text, public_raw out text, public_pem out text)
    RETURNS record
    AS 'jwt_context', 'jwt_generate_keys'
    LANGUAGE C VOLATILE;

CREATE OR REPLACE FUNCTION jwt_generate_secret(algo text)
    RETURNS text
    AS 'jwt_context', 'jwt_generate_secret'
    LANGUAGE C VOLATILE;
