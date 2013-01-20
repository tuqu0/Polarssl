#include "../include/unprotect_buffer.h"

unsigned char iv[16] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int getPaddingOffset(unsigned char* input_padd, int len)
{
	int i = 0;
	
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
	unsigned char *input_padd;
	unsigned char *cipher;
	unsigned char *plain;
	aes_context aes_ctx;
	sha2_context sha_ctx;

	/* *** Init *** */
	ret = 1;
	i = 0;
	offset = 0;
	input_padd = NULL;
	cipher = NULL;
	plain = NULL;

	/* *** Get cipher text *** */
	cipher = (unsigned char *) malloc((input_len - 32) * sizeof(char));
	if (cipher == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	memcpy(cipher, input, input_len - 32);
	input_padd = (unsigned char *) malloc((input_len - 32) *
					       sizeof(char));
	if (input_padd == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	memcpy(tmp_2, input + (input_len - 32), 32);

	/* *** Deriv password to MasterKey *** */
	ret = deriv_passwd(k_m, password, salt, salt_len, iterations);
	if(ret != 0) {
		fprintf(stderr, "error: deriv_passwd failed\n");
		ret = 1;
		goto cleanup;
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
		ret = 1;
		goto cleanup;
	}

	/* *** Dechiffrement *** */
	ret = aes_setkey_dec(&aes_ctx, k_c, 256);
	if (ret != 0) {
		fprintf(stderr, "error : aes_setkey_dec failed\n");
		ret = 1;
		goto cleanup;
	}
	ret = aes_crypt_cbc(&aes_ctx, AES_DECRYPT, input_len - 32, iv,
			    cipher, input_padd);
	if (ret != 0) {
		fprintf(stderr, "error : aes_crypt_cbc failed\n");
		ret = 1;
		goto cleanup;
	}

	/* *** Padding *** */
	offset = getPaddingOffset(input_padd, input_len - 32);
	plain = (unsigned char *) malloc(offset * sizeof(char) + 1);
	if (plain == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	memcpy(plain, input_padd, offset);
    plain[offset * sizeof(char)] = '\0';

	/* *** Output *** */
	*output = plain;
	*output_len = offset;
	ret = 0;

cleanup:
	if (input_padd != NULL) {
		memset(input_padd, 0x00, input_len - 32);
		free(input_padd);
	}

	if (cipher != NULL) {
		memset(cipher, 0x00, input_len - 32);
		free(cipher);
	}
	memset(&aes_ctx, 0x00, sizeof(aes_context));

	memset(&sha_ctx, 0x00, sizeof(sha_ctx));

	memset(k_m, 0x00, 32);

	memset(k_c, 0x00, 32);

	memset(k_i, 0x00, 32);

	memset(tmp_1, 0x00, 36);

	memset(tmp_2, 0x00, 32);

	i = 0;
	
	return ret;
}
