int jwt_es256_sign(const uint8 *secret, int secretlen,
				   const char *payload,
				   uint8 *sig, int siglen);

bool jwt_es256_verify(const uint8 *secret, int secretlen,
					  const char *payload,
					  uint8 *sig, int siglen);

void jwt_es256_genkey(char **privkey_raw, char **privkey_pem,
					  char **pubkey_raw, char **pubkey_pem);
