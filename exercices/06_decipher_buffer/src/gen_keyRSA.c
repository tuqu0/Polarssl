#include "../include/gen_keyRSA.h"

int gen_keyRSA()
{
	int ret;
	ctr_drbg_context drbg_ctx;
	entropy_context entropy_ctx;
	rsa_context rsa_ctx;
	FILE *f;

	/* *** Init *** */
	entropy_init(&entropy_ctx);
	ret = ctr_drbg_init(&drbg_ctx, entropy_func, &entropy_ctx, NULL, 0);
	if (ret != 0) {
		fprintf(stderr, "error : ctr_drbg_init fails\n");
		ret = 1;
		goto cleanup;
	}

	/* *** Generate RSA key *** */
	rsa_init(&rsa_ctx, RSA_PKCS_V15, 0);
	ret = rsa_gen_key(&rsa_ctx, ctr_drbg_random, &drbg_ctx, KEY_LEN, EXPONENT);
	if (ret != 0) {
		fprintf(stderr, "error : rsa_gen_key fails\n");
		ret = 1;
		goto cleanup;
	}

	/* *** Save public key *** */
	f = fopen("rsa.pub", "wb+");
	if (f == NULL) {
		fprintf(stderr, "error : unbale to write in rsa.pub\n");
		ret = 1;
		goto cleanup;
	}
	mpi_write_file("N = ", &rsa_ctx.N, 16, f);
	mpi_write_file("E = ", &rsa_ctx.E, 16, f);
	fclose(f);

	/* *** Save private key *** */
	f = fopen("rsa.priv", "wb+");
	if (f == NULL) {
		fprintf(stderr, "error : unable to write in rsa.priv\n");
		ret = 1;
		goto cleanup;
	}
	mpi_write_file("N = ", &rsa_ctx.N, 16, f);
	mpi_write_file("E = ", &rsa_ctx.E, 16, f);
	mpi_write_file("D = ", &rsa_ctx.D, 16, f);
	mpi_write_file("P = ", &rsa_ctx.P, 16, f);
	mpi_write_file("Q = ", &rsa_ctx.Q, 16, f);
	mpi_write_file("DP = ", &rsa_ctx.DP, 16, f);
	mpi_write_file("DQ = ", &rsa_ctx.DQ, 16, f);
	mpi_write_file("QP = ", &rsa_ctx.QP, 16, f);
	fclose(f);
	ret = 0;

cleanup:
	rsa_free(&rsa_ctx);
	return ret;
	
}
