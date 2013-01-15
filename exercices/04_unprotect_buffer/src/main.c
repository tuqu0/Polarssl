#include "../include/deriv_passwd.h"
#include "../include/unprotect_buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int print_hex(unsigned char *buffer, int buffer_len, char *id)
{
	int i;

	printf(">>> %s\n", id);
	for(i = 0; i < buffer_len; i++)
		printf("%02X", buffer[i]);
	printf("\n");
	
	return 0;
}

int main(int argc, char **argv)
{
	int c, i, ret, f_len, password_len, output_len;
	unsigned int iterations; 
	unsigned char key[32]; //SHA256 used
	unsigned char salt[16];
	char *password = NULL;
	unsigned char *output = NULL;
	unsigned char *input = NULL;
	FILE *f = NULL;

	/* *** check parameters *** */
	if (argc != 3) {
		fprintf(stderr, "usage : %s <password> <file>\n", argv[0]);
		return 1;
	}

	/* *** initialization *** */
	password_len = strlen(argv[1]);
	password = (char *) malloc(sizeof(char) * (password_len + 1));
	if (password == NULL) {
		fprintf(stderr, "error : memory allocation fails\n");
		password_len = 0;
		return 1;
	}
	strcpy(password, argv[1]);
	password[password_len] = '\0';
	memset(salt, 0x00, 16);
	iterations = 1<<5; // 32
	ret = 1;

	/* *** read ciphered text from given file *** */
	if ((f = fopen(argv[2], "r")) == 0) {
		fprintf(stderr, "unable to read %s\n", argv[2]);
		goto cleanup;
	}
	fseek(f, 0, SEEK_END);
	f_len = ftell(f);
	fseek(f, SEEK_SET, 0);
	input = (unsigned char *) malloc(sizeof(unsigned char) * f_len);
	if (input == NULL)
		goto cleanup;
	i = 0;
	while(fscanf(f, "%02X", &c) > 0 && i < f_len)
		input[i++] = (unsigned char) c;

	/* *** unprotect buffers *** */
	ret = unprotect_buffer(&output, &output_len, input, f_len / 2, password,
			       salt, 16, iterations);
	printf(">>> ret : %d\n", ret);
	print_hex(output, output_len, "OUTPUT");
	
	ret = 0;

cleanup:
	/* *** cleanup and return *** */
	if (f != NULL)
		fclose(f);
	if (input != NULL)
		free(input);
	memset(key, 0x00, 32);
	memset(password, 0x00, password_len);
	password_len = 0;
	free(password);
	memset(salt, 0x00, 16);
	iterations = 0;

	return ret;
}
