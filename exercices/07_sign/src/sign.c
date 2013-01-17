#include "../include/sign.h"

int sign(unsigned char *output, unsigned char *input, int input_len,
	 char *pri_key_file)
{
	int ret;
	unsigned char hash[32];
	rsa_context rsa_ctx;
	havege_state prng_ctx;
	FILE *f;

	/* *** Init *** */
	ret = 1;
	f = NULL;
	memset(hash, 0x00, 32);

	/* *** Get the private key *** */
	f = fopen(pri_key_file, "rb");
	if (f == NULL) {
		fprintf(stderr, "error : unable to open %s\n",
			pri_key_file);
		ret = 1;
		goto cleanup;
	}
	rsa_init(&rsa_ctx, RSA_PKCS_V15, 0);
	if (mpi_read_file(&rsa_ctx.N, 16, f) != 0
	    || mpi_read_file(&rsa_ctx.E, 16, f) != 0
	    || mpi_read_file(&rsa_ctx.D, 16, f) != 0
	    || mpi_read_file(&rsa_ctx.P, 16, f) != 0
	    || mpi_read_file(&rsa_ctx.Q, 16, f) != 0
	    || mpi_read_file(&rsa_ctx.DP, 16, f) != 0
	    || mpi_read_file(&rsa_ctx.DQ, 16, f) != 0
	    || mpi_read_file(&rsa_ctx.QP, 16, f) != 0) {
		fprintf(stderr, "error : unable to read private key\n");
		ret = 1;
		goto cleanup;
	}
	rsa_ctx.len = (mpi_msb(&rsa_ctx.N) + 7) >> 3;

	/* *** SHA-256 *** */
	sha2(input, input_len, hash, 0);

	/* *** Sign *** */
	havege_init(&prng_ctx);
	ret = rsa_pkcs1_sign(&rsa_ctx, havege_random, &prng_ctx,
			     RSA_PRIVATE,SIG_RSA_SHA256, 0, hash, output);

cleanup:
	if (f != NULL)
		fclose(f);
	
	memset(hash, 0x00, 32);

	memset(&prng_ctx, 0x00, sizeof(havege_state));

	rsa_free(&rsa_ctx);

	return ret;
}
