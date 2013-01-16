#include "../include/main.h"

int main(int argc, char **argv)
{
	int ret, input_len, cipher_len;
	unsigned char *cipher;
	unsigned char *s_key;
	char *input;

	/* *** Init *** */
	ret = 1;
	input_len = 0;
	cipher_len = 0;
	input = NULL;
	cipher = NULL;
	s_key = NULL;

	/* *** Check parameters *** */
	if (argc != 2) {
		fprintf(stderr, "usage : %s <message>\n", argv[0]);
		ret = 1;
		goto cleanup;
	}

	/* *** Get input text *** */
	input = (char *) malloc(strlen(argv[1]));
	if (input == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	strcpy(input, argv[1]);
	input_len = strlen(argv[1]);

	/* *** Generate symetric key *** */
	s_key = (unsigned char *) malloc(32 * sizeof(unsigned char));
	if (s_key == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	gen_key(s_key, 16);

	/* *** Generate RSA public/private keys *** */
	gen_keyRSA(PUBLIC_KEY, PRIVATE_KEY);

	/* *** Cipher *** */
	ret = cipher_buffer(&cipher, &cipher_len, 
			(unsigned char *) input, input_len,
			PUBLIC_KEY, s_key);
	if (ret != 0) {
		fprintf(stderr, "error : unable to cipher input text\n");
		ret = 1;
		goto cleanup;
	}

	/* *** Print ciphered text *** */
	print_hex(cipher, cipher_len, "cipher = ");

cleanup:
	if (input != NULL) {
		memset(input, 0, input_len);
		free(input);
		input_len = 0;
	}

	if (s_key != NULL) {
		memset(s_key, 0, 16);
		free(s_key);
	}
	cipher_len = 0;

	return ret;
}
