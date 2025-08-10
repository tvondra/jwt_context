#include <openssl/rand.h>

#include "postgres.h"

#include "common/base64.h"
#include "common/hmac.h"
#include "common/sha2.h"

#include "jwt_base64.h"
#include "jwt_hs256.h"

int
jwt_hs256_sign(const uint8 *secret, int secretlen,	/* input */
			   const char *payload, 				/* base64url-encoded */
			   uint8 *sig, int siglen)				/* output */
{
	/* hmac context */
	pg_hmac_ctx *ctx;
	pg_cryptohash_type	algo = PG_SHA256;

	/* buffer has enough space for the signature */
	Assert(siglen >= PG_SHA256_DIGEST_LENGTH);

	/* allocate a buffer */
	ctx = pg_hmac_create(algo);

	/* the string generated so far */
	pg_hmac_init(ctx, secret, secretlen);
	pg_hmac_update(ctx, (uint8 *) payload, strlen(payload));
	pg_hmac_final(ctx, sig, PG_SHA256_DIGEST_LENGTH);
	pg_hmac_free(ctx);

	return PG_SHA256_DIGEST_LENGTH;
}

bool
jwt_hs256_verify(const uint8 *secret, int secretlen,	/* input */
				 const char *payload, 					/* base64url-encoded */
				 uint8 *sig, int siglen)				/* input */
{
	/* new signature */
	uint8  *sig_new;

	pg_hmac_ctx *ctx;
	pg_cryptohash_type	algo = PG_SHA256;

	/* incorrect signature length, can't be valid */
	if (siglen != PG_SHA256_DIGEST_LENGTH)
		return false;

	/* FIXME do the actual verification here */
	ctx = pg_hmac_create(algo);

	sig_new = palloc(siglen);

	pg_hmac_init(ctx, secret, secretlen);
	pg_hmac_update(ctx, (uint8 *) payload, strlen(payload));
	pg_hmac_final(ctx, sig_new, siglen);
	pg_hmac_free(ctx);

	/* compare the signatures */
	return (memcmp(sig, sig_new, siglen) == 0);
}

void
jwt_hs256_gensecret(char **secret)
{
	int		rc;
	int		len = 64;	/* 512 bits (which should be the max for HMAC) */
	uint8  *buffer = palloc(len);
	char   *buffer_b64 = palloc0(pg_b64_enc_len(len) + 1);

	rc = RAND_bytes(buffer, len);
	if (rc != 1)
		elog(ERROR, "RAND_bytes failed");

	if (b64url_encode(buffer, len, buffer_b64, pg_b64_enc_len(len)) == -1)
		elog(ERROR, "encoding secret failed");

	*secret = buffer_b64;
}
