int jwt_hs256_sign(const uint8 *secret, int secretlen,
				   const char *payload,
				   uint8 *sig, int siglen);

bool jwt_hs256_verify(const uint8 *secret, int secretlen,
					  const char *payload,
					  uint8 *sig, int siglen);

void jwt_hs256_gensecret(char **secret);
