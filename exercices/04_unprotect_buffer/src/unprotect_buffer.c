#include "../include/unprotect_buffer.h"

const unsigned char padding[16] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int unprotect_buffer(unsigned char **output, int *output_len,
		     unsigned char *input, int input_len,
		     char *password,
		     unsigned char *salt, int salt_len,
    		     unsigned int iterations)
{
	int ret;
	int i;
	unsigned char k_m[32];
	unsigned char k_c[32];
	unsigned char k_i[32];
	unsigned char tmp_1[36];
	int pad_len;
	unsigned char *input_padd;
	unsigned char *cipher;
	unsigned char iv[16];
	aes_context aes_ctx;


	/* *** Initialisation *** */
	input_padd = NULL;
	cipher = NULL;

	/* *** Deriv password to MasterKey *** */
	ret = deriv_passwd(k_m, password, salt, salt_len, iterations);
	if(ret != 0)
	{
		fprintf(stderr, "error: deriv_passwd\n");
		return 1;
	}

	/* *** Deriv MasterKey to CipherKey / IntegrityKey *** */
	i = 0;
	memcpy(tmp_1, k_m, 32);
	memcpy(tmp_1+32, &i, sizeof(int));
	sha2(tmp_1, 36, k_c, 0);
	i ++;
	memcpy(tmp_1, k_m, 32);
	memcpy(tmp_1+32, &i, sizeof(int));
	sha2(tmp_1, 36, k_i, 0);

	/* *** Padding ?! *** */
	pad_len = 16 - (input_len % 16);
	input_padd = (unsigned char *)malloc((input_len + pad_len)*sizeof(char));
	if(input_padd == NULL)
		goto cleanup;
	cipher = (unsigned char *)malloc((input_len + pad_len + 32)*sizeof(char));
	if(cipher == NULL)
		goto cleanup;
	memcpy(input_padd, input, input_len);
	memcpy(input_padd+input_len, padding, pad_len);

	/* *** Chiffrement *** */
	ret = aes_setkey_enc(&aes_ctx, k_c, 256);
	if(ret != 0)
		goto cleanup;

	ret = aes_crypt_cbc(&aes_ctx, AES_ENCRYPT, (size_t) (input_len + pad_len), (unsigned char *)iv, input_padd, cipher);

	//ret = aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, input_padd, cipher);
	
	if(ret != 0)
		goto cleanup;
	
	/* *** Ajout du controle d'integrite *** */
	sha2_hmac(k_i, 32, cipher, input_len+pad_len, cipher+input_len+pad_len, 0);

	*output = cipher;
	*output_len = input_len + pad_len + 32;

	ret = 0;
cleanup:
	if(input_padd != NULL)
		free(input_padd);
	if(cipher != NULL)
		free(cipher);
	memset(&aes_ctx, 0x00, sizeof(aes_context));
	memset(k_m, 0x00, 32);
	memset(k_c, 0x00, 32);
	memset(k_i, 0x00, 32);
	memset(tmp_1, 0x00, 36);

	return ret;
}
