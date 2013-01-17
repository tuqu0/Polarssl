#include "../include/main.h"

int main(int argc, char **argv)
{
	int c, i, ret, f_len, password_len, output_len;
	unsigned int iterations; 
	unsigned char key[32]; //SHA256 used
	unsigned char salt[16];
	char *password;
	char *output;
	unsigned char *input;
	FILE *f;

	/* *** check parameters *** */
	if (argc != 3) {
		fprintf(stderr, "usage : %s <password> <file>\n", argv[0]);
		return 1;
	}

	/* *** Init *** */
	c = 0;
	i = 0;
	f_len = 0;
	ret = 1;
	password_len = 0;
	output_len = 0;
	password = NULL;
	output = NULL;
	input = NULL;
	f = NULL;

	/* *** Get password *** */
	password_len = strlen(argv[1]);
	password = (char *) malloc(sizeof(char) * (password_len + 1));
	if (password == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	strcpy(password, argv[1]);
	password[password_len] = '\0';

	/* *** Set salt *** */
	memset(salt, 0x00, 16); // salt = 0x00 ... 0x00
	
	/* *** Set number of iterations *** */
	iterations = 1<<5; // 32

	/* *** read ciphered text from given file *** */
	if ((f = fopen(argv[2], "r")) == 0) {
		fprintf(stderr, "unable to open %s\n", argv[2]);
		goto cleanup;
	}
	fseek(f, 0, SEEK_END);
	f_len = ftell(f);
	fseek(f, SEEK_SET, 0);
	input = (unsigned char *) malloc(sizeof(unsigned char) * f_len);
	if (input == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	i = 0;
	while(fscanf(f, "%02X", &c) > 0 && i < f_len)
		input[i++] = (unsigned char) c;

	/* *** unprotect buffers *** */
	ret = unprotect_buffer((unsigned char **) &output, &output_len,
			       input, f_len / 2, password, salt, 16,
			       iterations);

	/* *** Print plain text *** */
	printf(">>> ret : %d\n", ret);
	if (ret == 0)
		printf(">>>OUTPUT\n %s\n", output);
	
cleanup:
	/* *** cleanup and return *** */
	if (f != NULL)
		fclose(f);

	if (input != NULL) {
		memset(input, 0x00, f_len);
		free(input);
	}
	f_len = 0;

	memset(key, 0x00, 32);

	if (password != NULL) {
		memset(password, 0x00, password_len);
		free(password);
	}
	password_len = 0;

	if (output != NULL) {
		memset(output, 0x00, output_len);
		free(output);
	}
	output_len = 0;

	memset(salt, 0x00, 16);

	iterations = 0;

	return ret;
}
