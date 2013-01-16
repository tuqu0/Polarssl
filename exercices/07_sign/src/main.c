#include "../include/main.h"

int main(int argc, char **argv)
{
	int ret, input_len;
	char *input;
	unsigned char output[128];

	/* *** Init *** */
	ret = 1;
	input = NULL;
	input_len = 0;
	memset(output, 0x00, 128);

	/* *** Check parameters *** */
	if (argc != 2) {
		fprintf(stderr, "usage : %s <message>\n", argv[0]);
		ret = 1;
		goto cleanup;
	}

	/* *** Get input message *** */
	input_len = strlen(argv[1]);
	input = (char *) malloc(input_len + 1);
	if (input == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	strcpy(input, argv[1]);
	input[input_len] = '\0';

	/* *** Generate RSA public/private keys *** */
	ret = gen_keyRSA(PUBLIC_KEY, PRIVATE_KEY);
	if (ret != 0) {
		fprintf(stderr, "error : unable to generate RSA keys\n");
		goto cleanup;
	}

	/* *** Sign *** */
	ret = sign(output, (unsigned char *) input, input_len,
		   PRIVATE_KEY);

	/* *** Print Signature *** */
	print_hex(output, 128, "signature = ");

cleanup:
	if (input != NULL) {
		memset(input, 0x00, input_len);
		free(input);
	}
	input_len = 0;

	memset(output, 0x00, 128);

	return ret;
}
