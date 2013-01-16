#include "../include/protect_buffer.h"

const unsigned char padding[16] =
{
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char iv[16] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int protect_buffer(unsigned char **output, int *output_len,
  		   unsigned char *input, int input_len,
		   char *password,
	 	   unsigned char *salt, int salt_len,
		   unsigned int iterations)
{
	int i, pad_len, ret;
	unsigned char k_m[32];
	unsigned char k_c[32];
	unsigned char k_i[32];
	unsigned char tmp_1[36];
	unsigned char *input_padd;
	unsigned char *cipher;
	aes_context aes_ctx;

	/* *** Init *** */
	i = 0;
	pad_len = 0;
	ret = 1;
	input_padd = NULL;
	cipher = NULL;

	/* *** Deriv password to MasterKey *** */
	ret = deriv_passwd(k_m, password, salt, salt_len, iterations);
	if(ret != 0) {
		fprintf(stderr, "error: deriv_passwd failed\n");
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

	/* *** Padding *** */
	pad_len = 16 - (input_len % 16);
	input_padd = (unsigned char *) malloc((input_len + pad_len) * 
					      sizeof(char));
	if(input_padd == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	cipher = (unsigned char *)malloc((input_len + pad_len + 32) * 
					 sizeof(char));
	if(cipher == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	memcpy(input_padd, input, input_len);
	memcpy(input_padd+input_len, padding, pad_len);

	/* *** Chiffrement *** */
	ret = aes_setkey_enc(&aes_ctx, k_c, 256);
	if(ret != 0) {
		fprintf(stderr, "error : aes_setkey_enc failed\n");
		ret = 1;
		goto cleanup;
	}
	ret = aes_crypt_cbc(&aes_ctx, AES_ENCRYPT, (size_t)
			    (input_len + pad_len), iv, input_padd, cipher);
	if(ret != 0) {
		fprintf(stderr, "error : aes_crypt_cbc failed\n");
		ret = 1;
		goto cleanup;
	}
	
	/* *** Ajout du controle d'integrite *** */
	sha2_hmac(k_i, 32, cipher, input_len + pad_len, cipher +
		  input_len + pad_len, 0);

	*output = cipher;
	*output_len = input_len + pad_len + 32;
	ret = 0;

cleanup:
	if(input_padd != NULL) {
		memset(input_padd, 0x00, input_len + pad_len);
		free(input_padd);
	}

	memset(&aes_ctx, 0x00, sizeof(aes_context));

	memset(k_m, 0x00, 32);

	memset(k_c, 0x00, 32);

	memset(k_i, 0x00, 32);

	memset(tmp_1, 0x00, 36);

	pad_len = 0;
	i = 0;

	return ret;
}
