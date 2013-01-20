#include "../include/verif.h"

int verif(unsigned char *sign, unsigned char *input, int input_len,
	  char *pub_key_file)
{
	int ret;
	unsigned char hash[32];
	rsa_context rsa_ctx;
	FILE *f;

	/* *** Init *** */
	ret = 1;
	memset(hash, 0x00, 32);
	f = NULL;

	/* *** Get public key *** */
	f = fopen(pub_key_file, "rb");
	if (f == NULL) {
		fprintf(stderr, "error : unable to open %s\n",
			pub_key_file);
		ret = 1;
		goto cleanup;
	}
	rsa_init(&rsa_ctx, RSA_PKCS_V15, 0);
	if (mpi_read_file(&rsa_ctx.N, 16, f) != 0
	    || mpi_read_file(&rsa_ctx.E, 16, f) != 0) {
		fprintf(stderr, "error : unable to read public key\n");
		ret = 1;
		goto cleanup;
	}
	rsa_ctx.len = (mpi_msb(&rsa_ctx.N) + 7) >> 3;

	/* *** SHA-256 *** */
	sha2(input, input_len, hash, 0);

	/* *** Check key *** */
	ret = rsa_pkcs1_verify(&rsa_ctx, RSA_PUBLIC, SIG_RSA_SHA256,
			       128, hash, sign);

cleanup:
	if (f != NULL)
		fclose(f);

	memset(hash, 0x00, 32);

	rsa_free(&rsa_ctx);
	return ret;
}
