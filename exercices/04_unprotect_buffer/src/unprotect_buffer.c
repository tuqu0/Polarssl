#include "../include/unprotect_buffer.h"

unsigned char iv[16] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int getPaddingOffset(unsigned char* input_padd, int len)
{
	int i = -1;
	
	for (i = len - 1; i >= 0; i--)
		if (input_padd[i] == 0x80)
			return i;
	return i;	
}

int unprotect_buffer(unsigned char **output, int *output_len,
		     unsigned char *input, int input_len,
		     char *password,
		     unsigned char *salt, int salt_len,
    		     unsigned int iterations)
{
	int ret, i, offset;
	unsigned char k_m[32];
	unsigned char k_c[32];
	unsigned char k_i[32];
	unsigned char tmp_1[36];
	unsigned char tmp_2[32];
	unsigned char *input_padd = NULL;
	unsigned char *cipher = NULL;
	unsigned char *plain = NULL;
	aes_context aes_ctx;
	sha2_context sha_ctx;

	/* *** Initialisation *** */
	cipher = (unsigned char *) malloc((input_len - 32) * sizeof(char));
	input_padd = (unsigned char *) malloc((input_len - 32) * sizeof(char));
	if (cipher == NULL || input_padd == NULL) {
		fprintf(stderr, "error : memory allocation fails\n");
		return 1;
	}

	memcpy(tmp_2, input + (input_len - 32), 32);
	memcpy(cipher, input, input_len - 32);

	/* *** Deriv password to MasterKey *** */
	ret = deriv_passwd(k_m, password, salt, salt_len, iterations);
	if(ret != 0) {
		fprintf(stderr, "error: deriv_passwd\n");
		return 1;
	}

	/* *** Deriv MasterKey to CipherKey / IntegrityKey *** */
	i = 0;
	memcpy(tmp_1, k_m, 32);
	memcpy(tmp_1+32, &i, sizeof(int));
	sha2(tmp_1, 36, k_c, 0);
	i++;
	memcpy(tmp_1, k_m, 32);
	memcpy(tmp_1+32, &i, sizeof(int));
	sha2(tmp_1, 36, k_i, 0);

	/* *** Calculate the integrity key with the given password *** */
	sha2_hmac_starts(&sha_ctx, k_i, 32, 0);
	sha2_hmac_update(&sha_ctx, cipher, input_len - 32);
	sha2_hmac_finish(&sha_ctx, k_i);

	/* *** Comparison *** */
	if (memcmp(k_i, tmp_2, 32) != 0) {
		fprintf(stderr, "error : keys are differents\n");
		goto cleanup;
	}

	/* *** Dechiffrement *** */
	ret = 1;
	ret = aes_setkey_dec(&aes_ctx, k_c, 256);
	if (ret != 0) {
		fprintf(stderr, "error : unable to set the key\n");
		goto cleanup;
	}
	ret = aes_crypt_cbc(&aes_ctx, AES_DECRYPT, input_len - 32, iv, cipher, input_padd);
	if (ret != 0) {
		fprintf(stderr, "error : unable to decrypt\n");
		goto cleanup;
	}

	/* *** Padding *** */
	offset = getPaddingOffset(input_padd, input_len - 32);
	plain = (unsigned char *) malloc(offset * sizeof(char));
	if (plain == NULL)
		goto cleanup;
	memcpy(plain, input_padd, offset);

	/* *** Output *** */
	*output = plain;
	*output_len = offset;
	ret = 0;

cleanup:
	if (input_padd != NULL)
		free(input_padd);
	if (cipher != NULL)
		free(cipher);
	if (plain != NULL)
		free(plain);
	memset(&aes_ctx, 0x00, sizeof(aes_context));
	memset(&sha_ctx, 0x00, sizeof(sha_ctx));
	memset(k_m, 0x00, 32);
	memset(k_c, 0x00, 32);
	memset(k_i, 0x00, 32);
	memset(tmp_1, 0x00, 36);
	memset(tmp_2, 0x00, 32);

	return ret;
}
