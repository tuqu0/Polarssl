#include "../include/gen_keyRSA.h"
#include "../include/decipher_buffer.h"
#include "../include/gen_key.h"
#include <stdlib.h>

int main(int argc, char **argv)
{
	int i, c, plain_len, f_len, ret;
	char *plain;
	unsigned char *cipher;
	FILE *f = NULL;

	/* *** Check parameters *** */
	if (argc != 3) {
		fprintf(stderr, "usage : %s <ciphered_file> <rsa.priv>\n", argv[0]);
		return 1;
	}

	/* **** Get the ciphered text *** */
	ret = 1;
	f = fopen(argv[1], "rb");
	if (f == NULL) {
		fprintf(stderr, "error : unable to read %s\n", argv[1]);
		ret = 1;
		goto cleanup;
	}
	fseek(f, 0, SEEK_END);
	f_len = ftell(f);
	fseek(f, SEEK_SET, 0);
	cipher = (unsigned char *) malloc(sizeof(unsigned char) * f_len);
	if (cipher == NULL) {
		fprintf(stderr, "error : memory allocation fails\n");
		ret = 1;
		goto cleanup;
	}
	i = 0;
	while (fscanf(f, "%02X", &c) > 0 && i < f_len)
		cipher[i++] = (unsigned char) c;

	/* *** Decipher the message *** */
	ret = decipher_buffer((unsigned char **) &plain, &plain_len, cipher, f_len / 2, argv[2]);
	if (ret != 0) {
		ret = 1;
		goto cleanup;
	}
	
	/* *** Display the plain text *** */
	printf("message : %s\n", plain);
	ret = 0;

cleanup:
	if (f != NULL)
		fclose(f);
	return ret;
}
