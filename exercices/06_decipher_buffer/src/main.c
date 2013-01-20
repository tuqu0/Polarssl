#include "../include/main.h"

int main(int argc, char **argv)
{
	int ret, cipher_len, plain_len, i, c;
	unsigned char *cipher;
	char *plain;
	FILE *f;

	/* *** Init *** */
	ret = 1;
	i = 0;
	cipher_len = 0;
	plain_len = 0;
	cipher = NULL;
	plain = NULL;
	f = NULL;

	/* *** Check parameters *** */
	if (argc != 3) {
		fprintf(stderr, "usage : %s <file> <private_key>\n",
			argv[0]);
		ret = 1;
		goto cleanup;
	}

	/* *** Get ciphered buffer *** */
	f = fopen(argv[1], "rb");
	if (f == NULL) {
		fprintf(stderr, "error : unable to open %s\n", argv[1]);
		ret = 1;
		goto cleanup;
	}
	fseek(f, 0, SEEK_END);
	cipher_len = ftell(f) / 2;
	fseek(f, SEEK_SET, 0);
	cipher = (unsigned char *) malloc((cipher_len * 2) *
					  sizeof(unsigned char));
	if (cipher == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	i = 0;
	while (fscanf(f, "%02X", &c) > 0 && i < (cipher_len * 2))
		cipher[i++] = (unsigned char) c;

	/* *** Decipher *** */
	ret = decipher_buffer((unsigned char **) &plain, &plain_len,
			      cipher, cipher_len, argv[2]);
	if (ret != 0) {
		fprintf(stderr, "error : unable to decipher\n");
		ret = 1;
		goto cleanup;
	}

	/* *** Display plain text *** */
	printf(">>> plain =\n%s\n", plain);

cleanup:
	if (f != NULL)
		fclose(f);

	if (cipher != NULL) {
		memset(cipher, 0x00, (cipher_len * 2) *
		       sizeof(unsigned char));
		free(cipher);
	}
	cipher_len = 0;

	if (plain != 0) {
		memset(plain, 0x00, plain_len);
		free(plain);
	}
	plain_len = 0;

	i = 0;
	c = 0;

	return ret;
}
