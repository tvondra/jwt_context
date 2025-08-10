/*
 * jwt.c - context signed using PKI
 *
 * JWT context is a signed JSON document with arbitrary content, stored
 * in a GUC variable, accessible by a session. The values can be looked
 * up by key, and used in queries, RLS policies, etc.
 *
 * To make the context useful for RLS policies, the context needs to be
 * trusted against unauthorized modifications by non-authorized users.
 * This is provided by signatures (either symmetric or asymmetric).
 *
 * The JWT specifies a wide range of signature/encryption schemes. This
 * extension currently implements the most common schemes. Adding
 * support for additional schemes is not difficult, as long as there is
 * a library providing the primitives (hash/encryption algorithms).
 *
 * The context is managed as a regular GUC, which means it's subject to
 * RESET ALL. This is desirable for use in connection-pooling use cases,
 * where the context needs to be forgotten before handing over the
 * connection to someone else.
 *
 * Who initializes the context depends on the architecture and which
 * components are trusted. In can be either done by the connection poll
 * (or some other middleware component), before the connection is
 * handed over to the user/application. It may also be done by the
 * user, in which case it should only know it's own context (with a
 * valid signature).
 *
 * XXX The context cound be made settable only once, i.e. it would get
 * "sealed" and could not be changed even if the malicious user gets
 * access to a different token. But would be difficult to reset by the
 * connection pool.
 *
 * XXX There might be short expiration period, built into the context
 * value (the timestamp would be part of it), after which it'd not be
 * allowed to set. Requires a more automated workflow. Get a token, as
 * part of login into the system, pass it to the connection pool. This
 * idea reminds me the tickets in kerberos.
 *
 * XXX This relies on "public key" for verifying signatures. This must
 * be protected against changes by users, otherwise the user might set
 * the key to whatever, and then sign arbitrary contexts. PGC_SUSET
 * seems about right, and it allows per-database (or per-role) keys.
 *
 *
 * Copyright (C) Tomas Vondra, 2025
 */

#include "postgres.h"

#include "catalog/pg_collation.h"
#include "common/base64.h"
#include "common/hmac.h"
#include "common/sha2.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/json.h"
#include "utils/jsonb.h"

#include "jwt_base64.h"
#include "jwt_context.h"
#include "jwt_es256.h"
#include "jwt_hs256.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

void _PG_init(void);

/* keys and context */

static jwt_key *jwt_pubkey_ptr = NULL;
static char *jwt_pubkey_str = NULL;

static jwt_key *jwt_secret_ptr = NULL;
static char *jwt_secret_str = NULL;

static char *jwt_context_string = NULL;
static Datum jwt_context_jsonb;

/* supported algorithms */
static jwt_algorithm algos[] = {
	{
		"HS256",
		true,	/* secret (symmetric) key */
		jwt_hs256_sign,
		jwt_hs256_verify,
		NULL,
		jwt_hs256_gensecret
	},
	{
		"ES256",
		false,	/* public key */
		jwt_es256_sign,
		jwt_es256_verify,
		jwt_es256_genkey,
		NULL
	},
	{
		NULL, NULL, NULL, NULL
	}
};

/* prototypes */
PG_FUNCTION_INFO_V1(jwt_get);
PG_FUNCTION_INFO_V1(jwt_get_key);
PG_FUNCTION_INFO_V1(jwt_sign);
PG_FUNCTION_INFO_V1(jwt_verify);
PG_FUNCTION_INFO_V1(jwt_sign_p256);
PG_FUNCTION_INFO_V1(jwt_verify_p256);
PG_FUNCTION_INFO_V1(jwt_generate_keys);
PG_FUNCTION_INFO_V1(jwt_generate_secret);

Datum jwt_get(PG_FUNCTION_ARGS);
Datum jwt_get_key(PG_FUNCTION_ARGS);
Datum jwt_sign(PG_FUNCTION_ARGS);
Datum jwt_verify(PG_FUNCTION_ARGS);
Datum jwt_generate_keys(PG_FUNCTION_ARGS);
Datum jwt_generate_secret(PG_FUNCTION_ARGS);

static void jwt_pubkey_assign_hook(const char *newval, void *extra);
static bool jwt_pubkey_check_hook(char **newval, void **extra, GucSource source);
static const char *jwt_pubkey_show_hook(void);

static void jwt_secret_assign_hook(const char *newval, void *extra);
static bool jwt_secret_check_hook(char **newval, void **extra, GucSource source);
static const char *jwt_secret_show_hook(void);

static bool jwt_context_check_hook(char **newval, void **extra, GucSource source);
static void jwt_context_assign_hook(const char *newval, void *extra);
static const char *jwt_context_show_hook(void);

static void jwt_parse_token(char *str, char **header, char **body, char **signature);
static bool jwt_verify_signature(jwt_key *key, char *msg, char **payload);

void
_PG_init(void)
{
	/*
	 * PGC_SIGHUP allows only one key in postgresql.conf, with PGC_SUSET we
	 * can have separate keys per database, etc. The risk is that if the
	 * user has privileged (superuser) role, he could set a key controls he
	 * controls.
	 * 
	 * XXX Maybe the GUC could be made as one-time-set, i.e. only the first
	 * set works, the following ones are ignored (i.e. once set, the key
	 * could not be changed).
	 */
	DefineCustomStringVariable("jwt.pubkey",
							   "Public key used for verification of signed contexts.",
							   NULL,
							   &jwt_pubkey_str,
							   "",
							   PGC_SUSET,	/* see comment above */
							   GUC_REPORT,
							   jwt_pubkey_check_hook,
							   jwt_pubkey_assign_hook,
							   jwt_pubkey_show_hook);

	DefineCustomStringVariable("jwt.secret",
							   "Secret used for verification of signed contexts.",
							   NULL,
							   &jwt_secret_str,
							   "",
							   PGC_SUSET,	/* see comment above */
							   GUC_REPORT,
							   jwt_secret_check_hook,
							   jwt_secret_assign_hook,
							   jwt_secret_show_hook);

	DefineCustomStringVariable("jwt.context",
							   "A string representing the current context contents.",
							   NULL,
							   &jwt_context_string,
							   "",
							   PGC_USERSET,
							   GUC_REPORT,
							   jwt_context_check_hook,
							   jwt_context_assign_hook,
							   jwt_context_show_hook);
}

/*
 * jwt_get
 *		return the context as a JSONB value
 *
 * Returns the context if valid, or NULL.
 */
Datum
jwt_get(PG_FUNCTION_ARGS)
{
	/* empty string => not set */
	if (strlen(jwt_context_string) != 0)
		PG_RETURN_DATUM(jwt_context_jsonb);

	PG_RETURN_NULL();
}

/*
 * jwt_get_key
 *		return the value for a key as text value, just like ->> operator
 *
 * Returns the context if valid, or NULL.
 */
Datum
jwt_get_key(PG_FUNCTION_ARGS)
{
	text   *key = PG_GETARG_TEXT_PP(0);

	LOCAL_FCINFO(fcinfo2, 2);
	Datum		result;

	/* empty string => not set */
	if (strlen(jwt_context_string) == 0)
		PG_RETURN_NULL();

	/* call json_object_field_text, might return NULL for missing keys */
	InitFunctionCallInfoData(*fcinfo2, NULL, 2, DEFAULT_COLLATION_OID, NULL, NULL);

	fcinfo2->args[0].value = jwt_context_jsonb;
	fcinfo2->args[0].isnull = false;
	fcinfo2->args[1].value = PointerGetDatum(key);
	fcinfo2->args[1].isnull = false;

	result = jsonb_object_field_text (fcinfo2);

	if (fcinfo2->isnull)
		PG_RETURN_NULL();

	PG_RETURN_DATUM(result);
}

static jwt_algorithm *
jwt_algorithm_lookup(char *algoname)
{
	jwt_algorithm *algo = algos;

	/* find scheme with matching name */
	while (algo->name != NULL)
	{
		if (strcmp(algoname, algo->name) == 0)
			return algo;

		algo++;
	}

	/* unsupported algorithms */
	elog(ERROR, "unknown/unsupported algorithm: %s", algoname);
}

/*
 * jwt_sign
 *		sign the provided context (header/body), using the symmetric key
 *
 * Returns a JWT string, which is a header.body.signature triplet with the
 * parts base64-encoded.
 *
 * Errors out if signature fails, which can happen for a number of reasons.
 */
Datum
jwt_sign(PG_FUNCTION_ARGS)
{
	char   *algoname = text_to_cstring(PG_GETARG_TEXT_PP(0));
	char   *key = text_to_cstring(PG_GETARG_TEXT_PP(1));
	char   *header = text_to_cstring(PG_GETARG_TEXT_PP(2));
	char   *body = text_to_cstring(PG_GETARG_TEXT_PP(3));

	int		len;
	char   *res,
		   *ptr,
		   *endptr PG_USED_FOR_ASSERTS_ONLY;

	/* symmetric key used for signature */
	int		key_len;
	uint8  *key_data;

	/* signature (digest) */
	int		signature_len;
	uint8  *signature_data;

	/*
	 * determine the signature algorithm
	 *
	 * XXX The algorithm should match the header, maybe extract it from there?
	 * Or at least cross-check it with that?
	 */
	jwt_algorithm  *algo = jwt_algorithm_lookup(algoname);

	/* allocate the buffers */
	key_len = pg_b64_dec_len(strlen(key));
	key_data = palloc(key_len);

	signature_len = SIGNATURE_MAX_LENGTH;
	signature_data = palloc(signature_len);

	/*
	 * decode the symmetric key, needs to be exactly key_len bytes
	 *
	 * XXX This may be too strict, the key might be longer (or perhaps even
	 * shorter, sacrificing some security). But having the expected size is
	 * probably good practice.
	 */
	key_len = b64url_decode(key, strlen(key), key_data, key_len);
	if (key_len == -1)
		elog(ERROR, "signature failed: unexpected length of secret key");

	/*
	 * Construct the output string to be signed - base64-encoded header
	 * and body, with '.' as delimiter. We allocate a buffer and then
	 * encode the header/body into it, calculate the signature and then
	 * also encode that.
	 *
	 * XXX We don't know the exact base64 length, so use the upper bound
	 * for a signature of a given length.
	 */
	len = pg_b64_enc_len(strlen(header)) +
		  pg_b64_enc_len(strlen(body)) +
		  pg_b64_enc_len(signature_len) +
		  3;	/* two separators + null terminator */

	/* allocate a buffer */
	res = palloc0(len);
	endptr = res + len;
	ptr = res;

	/* base64-encode header */
	len = b64url_encode((uint8 *) header, strlen(header),
						ptr, pg_b64_enc_len(strlen(header)));
	if (len == -1)
		elog(ERROR, "base64 encoding of header failed");

	ptr += len;
	Assert(ptr <= endptr);

	/* add the delimiter */
	*ptr = '.';
	ptr++;

	/* base64-encode body */
	len = b64url_encode((uint8 *) body, strlen(body),
						ptr, pg_b64_enc_len(strlen(body)));
	if (len == -1)
		elog(ERROR, "base64 encoding of body failed");

	ptr += len;
	Assert(ptr <= endptr);

	/* do the actual signing */
	signature_len = algo->sign(key_data, key_len, res, signature_data, signature_len);

	/* add the delimiter */
	*ptr = '.';
	ptr++;

	/* encode the signature */
	len = b64url_encode(signature_data, signature_len,
						ptr, pg_b64_enc_len(signature_len));
	if (len == -1)
		elog(ERROR, "base64 encoding of signature failed");

	ptr += len;
	Assert(ptr <= endptr);

	PG_RETURN_TEXT_P(cstring_to_text(res));
}

/*
 * jwt_verify
 *		verify signature on a context
 *
 * Returns true if signature is valid, false otherwise.
 */
Datum
jwt_verify(PG_FUNCTION_ARGS)
{
	jwt_key *key = NULL;
	char   *msg;

	/* if context is NULL, return NULL */
	if (PG_ARGISNULL(1))
		PG_RETURN_NULL();

	msg = text_to_cstring(PG_GETARG_TEXT_PP(1));

	/*
	 * If key was specified in the call, use that. Otherwise use either the
	 * secret or public key (chosen in jwt_verify_signature).
	 */
	if (!PG_ARGISNULL(0))
	{
		char *keystr = text_to_cstring(PG_GETARG_TEXT_PP(0));

		key = palloc0(sizeof(jwt_key));
		key->len = b64url_decode(keystr, strlen(keystr),
								 key->data, KEY_MAX_BYTES);

		if (key->len == -1)
			elog(ERROR, "failed to decode key");
	}

	PG_RETURN_BOOL(jwt_verify_signature(key, msg, NULL));
}

/*
 * helper to generate tuple descriptor for jwt_generate_keys()
 */
static TupleDesc
jwt_generate_keys_tupdesc(void)
{
	TupleDesc	tupdesc;

	tupdesc = CreateTemplateTupleDesc(4);

	TupleDescInitEntry(tupdesc, 1, "private_raw", TEXTOID, -1, 0);
	TupleDescInitEntry(tupdesc, 2, "private_pem", TEXTOID, -1, 0);
	TupleDescInitEntry(tupdesc, 3, "public_raw", TEXTOID, -1, 0);
	TupleDescInitEntry(tupdesc, 4, "public_pem", TEXTOID, -1, 0);

	return BlessTupleDesc(tupdesc);
}

/*
 * jwt_generate_keys
 *		convenience function to generate random public/secret key pair
 *
 * This uses openssl to generate a P256 keypair, used for the HS256 JWT
 * signing. The keys are returned both base64-encoded (with the url
 * encoding, just like everythin else in JWT) and in PEM format.
 *
 * XXX The JWT supports various other schemes with other key types (RSA,
 * and so on). That can be supported in the future.
 */
Datum
jwt_generate_keys(PG_FUNCTION_ARGS)
{
	char	   *algoname = text_to_cstring(PG_GETARG_TEXT_PP(0));
	TupleDesc	tupdesc;
	Datum		values[4];
	bool		nulls[4];

	/* base64-encoded keys (DER format) */
	char   *private_raw = NULL,
		   *public_raw = NULL;

	/* keys in PEM format */
	char   *private_pem = NULL,
		   *public_pem = NULL;

	jwt_algorithm  *algo = jwt_algorithm_lookup(algoname);

	if (!algo->genkey)
		elog(ERROR, "algorithm '%s' does not support 'genkey'", algoname);

	algo->genkey(&private_raw, &private_pem, &public_raw, &public_pem);

	/* no NULLs */
	memset(nulls, 0, sizeof(nulls));

	tupdesc = jwt_generate_keys_tupdesc();

	values[0] = PointerGetDatum(cstring_to_text(private_raw));
	values[1] = PointerGetDatum(cstring_to_text(private_pem));
	values[2] = PointerGetDatum(cstring_to_text(public_raw));
	values[3] = PointerGetDatum(cstring_to_text(public_pem));

	tupdesc = jwt_generate_keys_tupdesc();

	PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

/*
 * jwt_generate_secret
 *		convenience function to generate random secret
 */
Datum
jwt_generate_secret(PG_FUNCTION_ARGS)
{
	char	   *algoname = text_to_cstring(PG_GETARG_TEXT_PP(0));

	/* base64-encoded secret */
	char   *secret = NULL;

	jwt_algorithm  *algo = jwt_algorithm_lookup(algoname);

	if (!algo->gensecret)
		elog(ERROR, "algorithm '%s' does not support 'gensecret'", algoname);

	algo->gensecret(&secret);

	PG_RETURN_TEXT_P(cstring_to_text(secret));
}

/*
 * jwt_pubkey_check_hook
 *		check the public key when setting the GUC
 */
static bool
jwt_pubkey_check_hook(char **newval, void **extra, GucSource source)
{
	jwt_key  *key = NULL;

	/* no context value, means it's a reset - always allowed */
	if (strlen(*newval) == 0)
		return true;

	/* check the public key has reasonable length */
	if (strlen(*newval) > KEY_MAX_BYTES)
	{
		GUC_check_errmsg("failed to set key: key too long (%ld > %d)",
						 strlen(*newval), KEY_MAX_BYTES);
		return false;
	}

	/* decode the key */
#if PG_VERSION_NUM >= 160000
	key = guc_malloc(LOG, sizeof(jwt_key));
#else
	key = malloc(sizeof(jwt_key));
#endif
	if (!key)
	{
		GUC_check_errmsg("failed to allocate memory for key: OOM");
		return false;
	}

	/*
	 * Make sure we got exactly the right public key length (we know it
	 * should not be longer than crypto_sign_PUBLICKEYBYTES, thanks to
	 * the earlier check.
	 */
	key->len = b64url_decode(*newval, strlen(*newval),
							 key->data, KEY_MAX_BYTES);
	if (key->len == -1)
	{
		GUC_check_errmsg("failed to set public key: decoding failed");
		return false;
	}

	if (key->len < KEY_MIN_BYTES)
	{
		GUC_check_errmsg("failed to set public key: invalid key length (%d < %d)",
						 key->len, KEY_MIN_BYTES);
		return false;
	}

	/* seems ok */
	*extra = key;

	return true;
}

/*
 * jwt_pubkey_assign_hook
 *		finish setting the public/secret key, preprocessed by the check hook
 */
static void
jwt_pubkey_assign_hook(const char *newval, void *extra)
{
	jwt_key *key = (jwt_key *) extra;

	if (strlen(newval) == 0)
	{
		/* paranoia: zero the current key */
		jwt_pubkey_ptr = NULL;
		return;
	}

	/* copy the decoded value into the actual place */
	jwt_pubkey_ptr = key;
}

/*
 * jwt_key_show_hook
 *		simply show the (original) string representation of the key
 */
static const
char *jwt_pubkey_show_hook(void)
{
	if (!jwt_pubkey_ptr)
	return "";

	return jwt_pubkey_str;
}

/*
 * jwt_secret_check_hook
 *		check the public key when setting the GUC
 */
static bool
jwt_secret_check_hook(char **newval, void **extra, GucSource source)
{
	jwt_key  *key = NULL;

	/* no context value, means it's a reset - always allowed */
	if (strlen(*newval) == 0)
		return true;

	/* check the public key has reasonable length */
	if (strlen(*newval) > KEY_MAX_BYTES)
	{
		GUC_check_errmsg("failed to set key: key too long (%ld > %d)",
						 strlen(*newval), KEY_MAX_BYTES);
		return false;
	}

	/* decode the key */
#if PG_VERSION_NUM >= 160000
	key = guc_malloc(LOG, sizeof(jwt_key));
#else
	key = malloc(sizeof(jwt_key));
#endif
	if (!key)
	{
		GUC_check_errmsg("failed to allocate memory for key: OOM");
		return false;
	}

	/*
	 * Make sure we got exactly the right public key length (we know it
	 * should not be longer than crypto_sign_PUBLICKEYBYTES, thanks to
	 * the earlier check.
	 */
	key->len = b64url_decode(*newval, strlen(*newval),
							 key->data, KEY_MAX_BYTES);
	if (key->len == -1)
	{
		GUC_check_errmsg("failed to set public key: decoding failed");
		return false;
	}

	if (key->len < KEY_MIN_BYTES)
	{
		GUC_check_errmsg("failed to set public key: invalid key length (%d < %d)",
						 key->len, KEY_MIN_BYTES);
		return false;
	}

	/* seems ok */
	*extra = key;

	return true;
}

/*
 * jwt_secret_assign_hook
 *		finish setting the secret key, preprocessed by the check hook
 */
static void
jwt_secret_assign_hook(const char *newval, void *extra)
{
	jwt_key *key = (jwt_key *) extra;

	if (strlen(newval) == 0)
	{
		/* paranoia: zero the current key */
		jwt_secret_ptr = NULL;
		return;
	}

	/* copy the decoded value into the actual place */
	jwt_secret_ptr = key;
}

/*
 * jwt_secret_show_hook
 *		simply show the (original) string representation of the key
 */
static const
char *jwt_secret_show_hook(void)
{
	if (!jwt_secret_ptr)
		return "";

	/* only show for superusers */
	if (!superuser())
		return "(hidden)";

	return jwt_secret_str;
}

/*
 * jwt_context_check_hook
 *		check the context we're about to set into the GUC
 *
 * FIXME this leaks memory (payload and the string copy for parsing), we
 * shoud either free this or pass it through extra to assign hook.
 *
 */
static bool
jwt_context_check_hook(char **newval, void **extra, GucSource source)
{
	char   *payload;

	Datum	tmp;
	char   *ptr;
	void   *new;

	/* setting to empty string means resetting, always allow */
	if (strlen(*newval) == 0)
		return true;

	/*
	 * Extract the payload string (this verifies the signature and errors
	 * out if the signature is wrong). The key will be selected based on
	 * the algorithm info.
	 */
	if (!jwt_verify_signature(NULL, *newval, &payload))
	{
		GUC_check_errmsg("signature verification failed");
		return false;
	}

	tmp = DirectFunctionCall1(jsonb_in,
							  PointerGetDatum(payload));
	ptr = DatumGetPointer(tmp);

#if PG_VERSION_NUM >= 160000
	new = guc_malloc(LOG, VARSIZE_ANY(ptr) + VARHDRSZ);
#else
	new = malloc(VARSIZE_ANY(ptr) + VARHDRSZ);
#endif

	memcpy(VARDATA(new), VARDATA(ptr), VARSIZE_ANY(ptr));
	SET_VARSIZE(new, VARSIZE_ANY_EXHDR(ptr) + VARHDRSZ);

	if (false)
	{
		GUC_check_errmsg("failed to parse JSON context");
		return false;
	}

	*extra = new;

	return true;
}

/*
 * jwt_context_check_hook
 *		check the context we're about to set into the GUC
 *
 * XXXX should verify signature and do most of the parsing (move it from
 * the assign hook)
 *
 * XXX Should verify the format of the context key/value part, we might fail
 * after already forgetting the current context.
 */
static void
jwt_context_assign_hook(const char *newval, void *extra)
{
	/* setting to empty string means resetting, always allow */
	if (strlen(newval) == 0)
		return;

	/* use the extra, set by the check hook to store the JSON value */
	jwt_context_jsonb = PointerGetDatum(extra);
}

/*
 * jwt_context_show_hook
 *		format the current context as key/value pairs
 */
static const char *
jwt_context_show_hook(void)
{
	if (strlen(jwt_context_string) != 0)
	{
		Datum	t = DirectFunctionCall1(jsonb_out, jwt_context_jsonb);

		return DatumGetCString(t);
	}

	return "(not set)";
}

/*
 * jwt_parse_token
 *		parse the token into header / body / signature parts
 *
 * Errors out if the parsing did not succeed.
 *
 * This does not do any base64-decoding.
 */
static void
jwt_parse_token(char *str, char **header, char **body, char **signature)
{
	char   *ptr = str;
	char   *sep;
	int		len;

	/* header */
	sep = strchr(ptr, '.');
	if (sep == NULL)
		elog(ERROR, "failed to parse JWT token header (separator not found)");

	len = (sep - ptr);

	*header = palloc0(len + 1);
	memcpy(*header, ptr, len);

	ptr = (sep + 1);

	/* body */
	sep = strchr(ptr, '.');
	if (sep == NULL)
		elog(ERROR, "failed to parse JWT token body (separator not found)");

	len = (sep - ptr);

	*body = palloc0(len + 1);
	memcpy(*body, ptr, len);

	ptr = (sep + 1);

	/* */
	sep = strchr(ptr, '.');
	if (sep != NULL)
		elog(ERROR, "failed to parse JWT token signature (extra separator)");

	*signature = ptr;
	len = strlen(ptr);
}

/*
 * jwt_parse_algorithm
 *		Extract the "alg" key from the header, simply by calling the
 * 		built-in function backing the ->> operator.
 */
static char *
jwt_parse_algorithm(char *header)
{
	char   *decoded;
	int		decodedlen;
	text   *json;
	text   *key = cstring_to_text("alg");

	LOCAL_FCINFO(fcinfo, 2);
	Datum		result;

	decodedlen = pg_b64_dec_len(strlen(header));
	decoded = palloc0(decodedlen + 1);

	if (b64url_decode(header, strlen(header), (uint8 *) decoded, decodedlen) == -1)
		elog(ERROR, "failed to decode header");

	json = cstring_to_text(decoded);

	/* call json_object_field_text, might return NULL for missing keys */
	InitFunctionCallInfoData(*fcinfo, NULL, 2, DEFAULT_COLLATION_OID, NULL, NULL);

	fcinfo->args[0].value = PointerGetDatum(json);
	fcinfo->args[0].isnull = false;
	fcinfo->args[1].value = PointerGetDatum(key);
	fcinfo->args[1].isnull = false;

	result = json_object_field_text (fcinfo);

	if (fcinfo->isnull)
		PG_RETURN_NULL();

	return text_to_cstring(DatumGetTextP(result));
}

/*
 * verify_signature
 *		verify signature of a message
 *
 * Splits the message on the first ':' into signature:context, and then
 * verify the signature using the current public key.
 *
 * Returns true if signature is valid, false otherwise (in this case payload
 * is set to NULL). (Does not throw any errors, so that it can be used in GUC
 * check hooks.)
 */
static bool
jwt_verify_signature(jwt_key *key, char *msg, char **payload)
{
	bool	res;
	char   *header,
		   *body,
		   *signature;

	char   *str;

	char   *algoname;

	jwt_algorithm *algo;

	uint8  *signature_data;
	int		signature_len;

	Assert(key != NULL);

	/* split JWT token into three parts, errors out if parsing fails */
	jwt_parse_token(msg, &header, &body, &signature);

	/* parse the header and extract the algorithm name */
	algoname = jwt_parse_algorithm(header);

	/* match the algorithm specified in the JWT header */
	algo = jwt_algorithm_lookup(algoname);

	/*
	 * If the key was not specified, use either the secret or public key,
	 * depending on the algorithm info.
	 */
	if (!key)
	{
		key = (algo->is_symmetric) ? jwt_secret_ptr : jwt_pubkey_ptr;
	}

	/* at this point we must have a key */
	if (!key)
		elog(ERROR, "no key defined");

	signature_len = SIGNATURE_MAX_LENGTH;
	signature_data = palloc0(signature_len);

	/* decode signature */
	signature_len = b64url_decode(signature, strlen(signature),
								  signature_data, signature_len);

	if (signature_len == -1)
		elog(ERROR, "failed to decode signature");

	/* build the signed payload again */
	str = palloc0(strlen(header) + strlen(body) + 2);
	sprintf(str, "%s.%s", header, body);

	/* do the actual verification */
	res = algo->verify(key->data, key->len, str,
					   signature_data, signature_len);

	if (!res)
		return false;

	/* pass the body back */
	if (payload)
	{
		int len = pg_b64_dec_len(strlen(body) + 1);
		*payload = palloc0(len);
		b64url_decode(body, strlen(body), (uint8 *) *payload, (strlen(body) + 1));
	}

	return true;
}
