#include "../include/main.h"

int main(int argc, char **argv)
{
	int ret, password_len, input_len, output_len;
	unsigned char key[32]; //SHA256 used
	unsigned char salt[16];
	unsigned char *input;
	unsigned int iterations;
	char *password;
	unsigned char *output;

	/* *** check parameters *** */
	if (argc != 3) {
		fprintf(stderr, "usage : %s <password> <message>\n",
			argv[0]);
		return 1;
	}

	/* *** initialization *** */
	ret = 1;
	password = NULL;
	input_len = NULL;
	output = NULL;
	password_len = 0;
	input_len = 0;
	output_len = 0;
	iterations = 0;

	/* *** get password *** */
	password_len = strlen(argv[1]);
	password = (char *) malloc(sizeof(char) * (password_len + 1));
	if (password == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;	
	}
	strcpy(password, argv[1]);
	password[password_len] = '\0';

	/* *** set input text *** */
	input_len = strlen(argv[2]);
	input = (char *) malloc(input_len + 1);
	if (input == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	strcpy(input, argv[2]);
	input[input_len] = '\0';

	/* *** set salt *** */
	memset(salt, 0x00, 16); //salt = 0x00 ... 0x00

	/* *** set number of iterations *** */
	iterations = 1<<5; //32
	
	/* *** protect buffers *** */
	ret = protect_buffer(&output, &output_len, input, input_len,
			     password, salt, 16, iterations);

	/* *** print protect buffer *** */
	printf(">>> ret : %d\n", ret);
	print_hex(output, output_len, "OUTPUT");
	
	ret = 0;

cleanup:
	/* *** cleanup and return *** */
	memset(key, 0x00, 32);

	if (password != NULL) {
		memset(password, 0x00, password_len);
		free(password);
	}
	password_len = 0;

	if (input != NULL) {
		memset(input, 0x00, input_len);
		free(input);
	}
	input_len = 0;

	memset(salt, 0x00, 16);

	if (output != NULL) {
		memset(output, 0x00, output_len);
		free(output);
	}
	output_len = 0;

	iterations = 0;

	return ret;
}
