#include "../include/cipher_buffer.h"

int cipher_buffer(unsigned char **output, int *output_len, 
        		  unsigned char *input, int input_len, 
		          char *public_key, unsigned char *key)
{
	int ret;
	unsigned int padd_len;
	unsigned char rsa_out[128];
	havege_state prng_ctx;
	aes_context aes_ctx;
	rsa_context rsa_ctx;
	unsigned char *padd, *out;
	FILE *f;

	/* *** Init *** */
	ret = 1;
	padd_len = 0;
	padd = NULL;
	out = NULL;
	f = NULL;

    unsigned char iv[16] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	unsigned char padding[16] = {
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	/* *** Get RSA public key *** */
	f = fopen(public_key, "rb");
	if (f == NULL) {
		fprintf(stderr, "error : unable to open %s\n", public_key);
		ret = 1;
		goto cleanup;
	}
	rsa_init( &rsa_ctx, RSA_PKCS_V15, 0 );
	if (mpi_read_file(&rsa_ctx.N, 16, f) != 0
	    || mpi_read_file(&rsa_ctx.E, 16, f) != 0) {
		fprintf(stderr, "error : unable to read public key\n");
		ret = 1;
		goto cleanup;
	}
	rsa_ctx.len = (mpi_msb(&rsa_ctx.N) + 7) >> 3;
	
	ret = aes_setkey_enc(&aes_ctx, key, 256);

	/* *** Padding *** */
	padd_len = 16 - (input_len % 16);
	padd = (unsigned char *) malloc((input_len + padd_len) * 
                                    sizeof(unsigned char));
	if (padd == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	memset(padd, 0, input_len + padd_len);
	out = (unsigned char *) malloc((input_len + padd_len) *
                                   sizeof(unsigned char));
	if (out == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	memset(out, 0 , input_len + padd_len);
	memcpy(padd, input, input_len);
	memcpy(padd + input_len, padding, padd_len);

	/* *** Cipher *** */
	ret = aes_crypt_cbc(&aes_ctx, AES_ENCRYPT, input_len + padd_len, 
			    iv, padd, out);
	if (ret != 0) {
		fprintf(stderr, "error : aes_crypt_cbc failed\n");
		ret = 1;
		goto cleanup;
	}
	havege_init(&prng_ctx);
	ret = rsa_pkcs1_encrypt(&rsa_ctx, havege_random, &prng_ctx, 
				RSA_PUBLIC, 16, key, rsa_out);
	if (ret != 0) {
		fprintf(stderr, "error : rsa_pkcs1_encrypt failed\n");
		ret = 1;
		goto cleanup;
	}
	
 	/* *** Output *** */
	*output = (unsigned char *) malloc((128 + input_len + padd_len) *
                                        sizeof(unsigned char));
	if (*output == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	memcpy(*output, rsa_out, 128);
	memcpy(*output+128, out, input_len + padd_len);
	*output_len = 128 + input_len + padd_len;

cleanup:
	if (f != NULL)
		fclose(f);
	rsa_free(&rsa_ctx);

	return ret;
}
