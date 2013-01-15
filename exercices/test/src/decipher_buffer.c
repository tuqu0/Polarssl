#include "../include/decipher_buffer.h"

unsigned char iv_[16] = 
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int decipher_buffer(unsigned char **output, int *output_len,
		    unsigned char *input, int input_len,
		    char *pri_key_file)
{
	int offset, ret;
	size_t key_len = 0;
	unsigned char s_key[16];
	rsa_context rsa_ctx;
	aes_context aes_ctx;
	FILE *f = NULL;

	/* *** Get the private key *** */
	f = fopen(pri_key_file, "rb");
	if (f == NULL) {
		fprintf(stderr, "error : unable to read %s\n", pri_key_file);
		ret = 1;
		goto cleanup;
	}
	rsa_init(&rsa_ctx, RSA_PKCS_V15, 0);
	if (mpi_read_file(&rsa_ctx.N, 16, f) != 0 || mpi_read_file(&rsa_ctx.E, 16, f) != 0 
	    || mpi_read_file(&rsa_ctx.D, 16, f) != 0 || mpi_read_file(&rsa_ctx.P, 16, f) != 0
	    || mpi_read_file(&rsa_ctx.Q, 16, f) != 0 ||	mpi_read_file(&rsa_ctx.DP, 16, f) != 0
	    || mpi_read_file(&rsa_ctx.DQ, 16, f) != 0 || mpi_read_file(&rsa_ctx.QP, 16, f) != 0) {
		fprintf(stderr, "error : unable to read private key\n");
		ret = 1;
		goto cleanup;
	}
	rsa_ctx.len = (mpi_msb(&rsa_ctx.N) + 7) >> 3;

	/* *** Get the symetric key *** */
	ret = rsa_pkcs1_decrypt(&rsa_ctx, RSA_PRIVATE, &key_len, input, s_key, 16);
	if (ret != 0) {
		fprintf(stderr, "error : rsa_pkcs1 fails\n");
		ret = 1;
		goto cleanup;
	}

	/* *** Decipher key *** */
	ret = aes_setkey_dec(&aes_ctx, s_key, 256);
	if (ret != 0) {
		fprintf(stderr, "error : aes_setkey_dec fails\n");
		ret = 1;
		goto cleanup;
	}

	/* *** Decipher *** */
	*output = (unsigned char *) malloc((input_len - 128) * sizeof(unsigned char));
	if (*output == NULL) {
		fprintf(stderr, "error : memory allocation fails\n");
		ret = 1;
		goto cleanup;
	}
	memset(*output, 0, input_len - 128);
	ret = aes_crypt_cbc(&aes_ctx, AES_DECRYPT, input_len - 128, iv_, input + 128, *output);
	if (ret != 0) {
		fprintf(stderr, "error : aes_cryp_cbc fails\n");
		ret = 1;
		goto cleanup;
	}

	/* *** Remove padding *** */
	for (offset = input_len - 128 - 1; offset >= 0; offset--) {
		if ((*output)[offset] == 0x80) {
			*output_len = offset;
			(*output)[offset] = 0x00;
			break;
		}
	}
	
cleanup:
	if (f != NULL)
		fclose(f);
	offset = 0;
	key_len = 0;
	rsa_free(&rsa_ctx);
	memset(&aes_ctx, 0, sizeof(aes_context));
	return ret;
}
