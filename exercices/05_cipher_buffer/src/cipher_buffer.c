#include "../include/cipher_buffer.h"

unsigned char padding[16] = 
{
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char iv[16] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int cipher_buffer(unsigned char **output, int *output_len,
		  unsigned char *input, int input_len,
		  char *pub_key_file, unsigned char *key)
{
	int ret;
	unsigned int padd_len;
	unsigned char rsa_out[128];
	rsa_context rsa_ctx;
	aes_context aes_ctx;
	havege_state prng_ctx;
	unsigned char *padd, *out;
	FILE *f = NULL;

	/* *** Read public key file *** */
	f = fopen(pub_key_file, "rb");
	if (f == NULL) {
		ret = 1;
		fprintf(stderr, "error : can not read %s\n", pub_key_file);
		goto cleanup;
	}
	rsa_init(&rsa_ctx, RSA_PKCS_V15, 0);
	mpi_read_file(&rsa_ctx.N, 16, f);
	mpi_read_file(&rsa_ctx.E, 16, f);
	fclose(f);
	rsa_ctx.len = (mpi_msb(&rsa_ctx.N) + 7) >> 3;

	/* *** Init AES *** */
	ret = aes_setkey_enc(&aes_ctx, key, 256);
	if (ret != 0) {
		fprintf(stderr, "error : aes_setkey_enc fails\n");
		ret = 1;
		goto cleanup;
	}

	/* *** Padding *** */
	padd_len = 16 - (input_len % 16);
	padd = (unsigned char *) malloc((input_len + padd_len) * sizeof(unsigned char));
	out = (unsigned char *) malloc((input_len + padd_len) * sizeof(unsigned char));
	if (padd == NULL || out == NULL) {
		fprintf(stderr, "error : memory allocation fails\n");
		ret = 1;
		goto cleanup;
	}
	memset(padd, 0, input_len + padd_len);
	memset(out, 0, input_len + padd_len);
	memcpy(padd, input, input_len);
	memcpy(padd + input_len, padding, padd_len);

	/* *** AES-256-CBC *** */
	ret = aes_crypt_cbc(&aes_ctx, AES_ENCRYPT, input_len + padd_len, iv, padd, out);
	if (ret != 0) {
		fprintf(stderr, "error : aes_cryt_cbc fails\n");
		ret = 1;
		goto cleanup;
	}

	/* *** Cipher key with RSA-1024 *** */
	havege_init(&prng_ctx);
	ret = rsa_pkcs1_encrypt(&rsa_ctx, havege_random, &prng_ctx, RSA_PUBLIC, 16, key, rsa_out);
	if (ret != 0) {
		fprintf(stderr, "error : rsa_pkcs1_encrypt fails\n");
		ret = 1;
		goto cleanup;
	}

	/* *** Cipher *** */
	*output = (unsigned char *) malloc((128 + input_len + padd_len) * sizeof(unsigned char));
	if (*output == NULL) {
		fprintf(stderr, "error : memory allocations fails\n");
		ret =1;
		goto cleanup;
	}
	memcpy(*output, rsa_out, 128);
	memcpy(*output + 128, out, input_len + padd_len);
	*output_len = 128 + input_len + padd_len;

cleanup:
	rsa_free(&rsa_ctx);
	memset(&aes_ctx, 0, sizeof(aes_context));
	memset(&prng_ctx, 0, sizeof(havege_state));
	memset(rsa_out, 0, 128);
	padd_len = 0;

	return ret;
}
