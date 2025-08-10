/* 1kB ought to be enough for anybody */
#define SIGNATURE_MAX_LENGTH	1024

/* shared secret / public key */
#define KEY_MIN_BYTES	32
#define KEY_MAX_BYTES	1024

/* public or secret key */
typedef struct jwt_key
{
	char   *algo;
	int		len;
	uint8	data[KEY_MAX_BYTES];
} jwt_key;

typedef int (*jwt_sign_func) (const uint8 *secret, int secretlen,
							  const char *payload,
							  uint8 *sig, int siglen);
typedef bool (*jwt_verify_func) (const uint8 *secret, int secretlen,
								 const char *payload,
								 uint8 *sig, int siglen);
typedef void (*jwt_genkey_func) (char **privkey_raw, char **privkey_pem,
								 char **pubkey_raw, char **pubkey_pem);
typedef void (*jwt_gensecret_func) (char **secret);

typedef struct jwt_algorithm
{
	/* name of the JWT scheme */
	char			   *name;

	/* which key to use? */
	bool				is_symmetric;

	/* callbacks */
	jwt_sign_func		sign;
	jwt_verify_func		verify;
	jwt_genkey_func		genkey;
	jwt_gensecret_func	gensecret;
} jwt_algorithm;
