#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "postgres.h"

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
#include "jwt_es256.h"

/* export key pair in tradition PEM format */
static void
jwt_export_keys_pem(EVP_PKEY *key, char **pkey, char **pubkey)
{
	BIO *priv_bio = NULL,
		*pub_bio = NULL;

	int	private_len,
		public_len;

	/* export the keys in PEM format */
	priv_bio = BIO_new(BIO_s_mem());
	pub_bio = BIO_new(BIO_s_mem());

	if (!priv_bio || !pub_bio)
		goto cleanup;

	if (!PEM_write_bio_PrivateKey(priv_bio, key, NULL, NULL, 0, NULL, NULL))
		goto cleanup;

	if (!PEM_write_bio_PUBKEY(pub_bio, key))
		goto cleanup;

	private_len = BIO_pending(priv_bio);
	public_len = BIO_pending(pub_bio);

	*pkey = palloc0(private_len + 1);
	*pubkey = palloc0(public_len + 1);

	BIO_read(priv_bio, *pkey, private_len);
	BIO_read(pub_bio, *pubkey, public_len);

cleanup:
	BIO_free(priv_bio);
	BIO_free(pub_bio);
}

/* export keys in raw format (base64 url-encoded, no headers) */
static void
jwt_export_keys_raw(EVP_PKEY *key, char **pkey, char **pubkey)
{
	BIO *priv_bio = NULL,
		*pub_bio = NULL;

	int	private_len,
		public_len;

	uint8  *private_buf,
		   *public_buf;

	/* export the keys in PEM format */
	priv_bio = BIO_new(BIO_s_mem());
	pub_bio = BIO_new(BIO_s_mem());

	if (!priv_bio || !pub_bio)
		goto cleanup;

	/* DER format, without the headers */
	if (i2d_PrivateKey_bio(priv_bio, key) <= 0)
		goto cleanup;

	if (i2d_PUBKEY_bio(pub_bio, key) <= 0)
		goto cleanup;

	private_len = BIO_pending(priv_bio);
	public_len = BIO_pending(pub_bio);

	private_buf = palloc0(private_len);
	public_buf = palloc0(public_len);

	BIO_read(priv_bio, private_buf, private_len);
	BIO_read(pub_bio, public_buf, public_len);

	/* base64 encode the keys (allocate the terminator) */

	*pkey = palloc0(pg_b64_enc_len(private_len) + 1);
	*pubkey = palloc0(pg_b64_enc_len(public_len) + 1);

	/* JWT used url-encoding, so use it here too */

	if (b64url_encode(private_buf, private_len, *pkey, pg_b64_enc_len(private_len)) == -1)
		goto cleanup;

	if (b64url_encode(public_buf, public_len, *pubkey, pg_b64_enc_len(public_len)) == -1)
		goto cleanup;

cleanup:
	BIO_free(priv_bio);
	BIO_free(pub_bio);
}

///* read public part of P256 EC keypair from base64 url-encoded string */
//static EVP_PKEY *
//jwt_read_p256_public_key(char *key)
//{
//	EVP_PKEY *pkey = NULL;
//	BIO *bio = NULL;
//
//	/* XXX could the length be too low due to the base64 url-encoding? */
//	int		rawkeylen = pg_b64_dec_len(strlen(key));
//	uint8  *rawkey = palloc0(rawkeylen);
//
//	rawkeylen = b64url_decode(key, strlen(key), rawkey, rawkeylen);
//	if (rawkeylen == -1)
//		elog(ERROR, "failed to decode public key");
//
//	bio = BIO_new_mem_buf(rawkey, rawkeylen);
//	if (!bio)
//		elog(ERROR, "failed to read public key");
//
//	pkey = d2i_PUBKEY_bio(bio, NULL);
//	if (!pkey)
//		elog(ERROR, "failed to read public key");
//
//	BIO_free(bio);
//
//	return pkey;
//}
//
///* read private part of P256 EC keypair from base64 url-encoded string */
//static EVP_PKEY *
//jwt_read_p256_private_key(char *key)
//{
//	EVP_PKEY *pkey = NULL;
//	BIO *bio = NULL;
//
//	/* XXX could the length be too low due to the base64 url-encoding? */
//	int		rawkeylen = pg_b64_dec_len(strlen(key));
//	uint8  *rawkey = palloc0(rawkeylen);
//
//	rawkeylen = b64url_decode(key, strlen(key), rawkey, rawkeylen);
//	if (rawkeylen == -1)
//		elog(ERROR, "failed to decode private key");
//
//	bio = BIO_new_mem_buf(rawkey, rawkeylen);
//	if (!bio)
//		elog(ERROR, "failed to read private key");
//
//	pkey = d2i_PrivateKey_bio(bio, NULL);
//	if (!pkey)
//		elog(ERROR, "failed to read private key");
//
//	BIO_free(bio);
//
//	return pkey;
//}


void
jwt_es256_genkey(char **privkey_raw, char **privkey_pem,
				 char **pubkey_raw, char **pubkey_pem)
{
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY *pkey = NULL;

	/* initialize the EC key generator, using the P256 NIST curve */
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!pctx)
	{
		elog(WARNING, "openssl: failed to initialize EVP_PKEY_CTX");
		goto error;
	}

	if (EVP_PKEY_keygen_init(pctx) <= 0)
	{
		elog(WARNING, "openssl: failed to initialize EVP_PKEY_CTX keygen");
		goto error;
	}

	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0)
	{
		elog(WARNING, "openssl: failed to set curve to NID_X9_62_prime256v1");
		goto error;
	}

	/* generate the key */

	if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
	{
		elog(WARNING, "openssl: failed to generate key");
		goto error;
	}

	/* export raw keys (base64 encoded) */
	jwt_export_keys_raw(pkey, privkey_raw, pubkey_raw);

	/* export in PEM format */
	jwt_export_keys_pem(pkey, privkey_pem, pubkey_pem);

error:

	/* FIXME needs to check if the pointers are NULL? */
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pctx);

	return;
}

int
jwt_es256_sign(const uint8 *secret, int secretlen,	/* input */
			   const char *payload, 				/* base64url-encoded */
			   uint8 *sig, int siglen)				/* output */
{
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY   *pkey = NULL;
	BIO		   *bio = NULL;
	size_t		sig_len;

	bio = BIO_new_mem_buf(secret, secretlen);
	if (!bio)
		elog(ERROR, "failed to read key");

	/* raw signature */
	pkey = d2i_PrivateKey_bio(bio, NULL);
	if (!pkey)
		elog(ERROR, "failed to read key");

	/* sign the payload message */
	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		elog(ERROR, "failed to initialize EVP_MD_CTX");

	if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0)
		elog(ERROR, "failed to initialize digest");

	if (EVP_DigestSignUpdate(mdctx, payload, strlen(payload)) <= 0)
		elog(ERROR, "failed to add payload to digest");

	if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) <= 0)
		elog(ERROR, "failed to determine signature length");

	if (sig_len > siglen)
		elog(ERROR, "signature too long");

	if (EVP_DigestSignFinal(mdctx, sig, &sig_len) <= 0)
		elog(ERROR, "failed to calculate signature");

	EVP_MD_CTX_free(mdctx);

	return sig_len;
}

bool
jwt_es256_verify(const uint8 *secret, int secretlen,	/* input */
				 const char *payload, 					/* base64url-encoded */
				 uint8 *sig, int siglen)				/* input */
{
	int			ret;
	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY   *pkey = NULL;
	BIO		   *bio = NULL;

	bio = BIO_new_mem_buf(secret, secretlen);
	if (!bio)
		elog(ERROR, "failed to read key");

	pkey = d2i_PUBKEY_bio(bio, NULL);
	if (!pkey)
		elog(ERROR, "failed to read key");

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		elog(ERROR, "EVP_MD_CTX_new failed");

	if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0)
		elog(ERROR, "EVP_DigestVerifyInit failed");

	if (EVP_DigestVerifyUpdate(ctx, payload, strlen(payload)) <= 0)
		elog(ERROR, "EVP_DigestVerifyUpdate failed (payload)");

	ret = EVP_DigestVerifyFinal(ctx, sig, (size_t) siglen);

	BIO_free(bio);
	EVP_PKEY_free(pkey);

	return (ret == 1);
}
