#include "../include/main.h"

int main(int argc, char **argv)
{
	int ret, input_len, sign_len, i, c;
	char *input;
	unsigned char *sign;
	FILE *f;

	/* *** Init *** */
	ret = 1;
	i = 0;
	input_len = 0;
	sign_len = 0;
	input = NULL;
	sign = NULL;
	f = NULL;

	/* *** Check parameters *** */
	if (argc != 4) {
		fprintf(stderr, "usage : %s <file> <message> \
<public_key>\n", argv[0]);
		ret = 1;
		goto cleanup;
	}

	/* *** Get input message *** */
	input_len = strlen(argv[2]);
	input = (char *) malloc(input_len + 1);
	if (input == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	strcpy(input, argv[2]);
	input[input_len] = '\0';

	/* *** Get signature buffer from given file *** */
	f = fopen(argv[1], "rb");
	if (f == NULL) {
		fprintf(stderr, "error : unable to open %s\n", argv[1]);
		ret = 1;
		goto cleanup;
	}
	fseek(f, 0, SEEK_END);
	sign_len = ftell(f) / 2;
	fseek(f, SEEK_SET, 0);
	sign = (unsigned char *) malloc((sign_len * 2) *
					 sizeof(unsigned char));
	if (sign == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	i = 0;
	while (fscanf(f, "%02X", &c) > 0 && i < (sign_len * 2))
		sign[i++] = (unsigned char) c;

	/* *** Verif *** */
	ret = verif(sign, (unsigned char *) input, input_len, argv[3]);

	/* *** Print verif result *** */
	if (ret == 0)
		printf("Result : signature is valid\n");
	else
		printf("Result : signature is not valid\n");

cleanup:
	if (f != NULL)
		fclose(f);
	
	if (input != NULL) {
		memset(input, 0x00, input_len);
		free(input);
	}
	input_len = 0;

	if (sign != NULL) {
		memset(sign, 0x00, (sign_len * 2) * sizeof(unsigned char));
		free(sign);
	}
	sign_len = 0;

	i = 0;
	c = 0;

	return ret;
}
