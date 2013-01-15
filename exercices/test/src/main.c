#include "../include/gen_keyRSA.h"
#include "../include/cipher_buffer.h"
#include "../include/decipher_buffer.h"
#include "../include/gen_key.h"

void print_hex(unsigned char *buffer, int buffer_len, char *id)
{
	int i;
	
	printf(">>> %s\n", id);
	for (i = 0; i < buffer_len; i++)
		printf("%02X", buffer[i]);
	printf("\n");
}

int main(int argc, char **argv)
{
	char *input, *plain = NULL;
	unsigned char *cipher;
	int input_len, cipher_len, ret, plain_len = 0;
	unsigned char key[16];

	/* *** Check parameters *** */
	if (argc != 2) {
		fprintf(stderr, "usage : %s <message>\n", argv[0]);
		return 1;
	}

	/* **** Init *** */
	ret = 1;
	cipher_len = 0;
	input_len = strlen(argv[1]);
	input = (char *) malloc(input_len);
	if (input == NULL) {
		fprintf(stderr, "error : memory allocation fails\n");
		return ret;
	}
	memcpy(input, argv[1], input_len);

	/* *** Generate symetric key *** */
	gen_key(key, 16);

	/* *** Generate RSA key *** */
	gen_keyRSA();

	/* *** Cipher message *** */
	ret = cipher_buffer(&cipher, &cipher_len, (unsigned char *) input, input_len, "rsa.pub", key);

	/* *** Display ciphere text and len *** */
	print_hex(cipher, cipher_len, "cipher = ");

	ret = decipher_buffer((unsigned char **) &plain, &plain_len, cipher, cipher_len, "rsa.priv");
	printf("message : %s\n", plain);

	return ret;
}
