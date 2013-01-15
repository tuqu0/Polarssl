#include "../include/deriv_passwd.h"
#include "../include/protect_buffer.h"
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
	int ret, password_len, salt_len, input_len, output_len;
	unsigned char key[32]; //SHA256 used
	unsigned int iterations;
	char *password;
	unsigned char *salt, *input, *output;

	/* *** check parameters *** */
	if (argc != 5) {
		fprintf(stderr, "usage : %s <password> <plain_text> <salt> <iterations>\n", argv[0]);
		return 1;
	}
	else if (strlen(argv[3]) > 16) {
		fprintf(stderr, "error : salt too long (16 characters max)\n");
		return 1;
	}
	else if (!atoi(argv[4]) || atoi(argv[4]) < 1) {
		fprintf(stderr, "error : number of iterations must be a positive integer\n");
		return 1;
	}

	/* *** initialization *** */
	password_len = strlen(argv[1]);
	password = (char *) malloc(sizeof(char) * (password_len + 1));
	input_len = strlen(argv[2]);
	input = (unsigned char *) malloc(sizeof(unsigned char) * input_len);
	salt_len = strlen(argv[3]);
	salt = (unsigned char *) malloc(sizeof(unsigned char) * salt_len);
	if (password == NULL || input == NULL || salt == NULL) {
		fprintf(stderr, "error : memory allocation fails\n");
		password_len = 0;
		input_len = 0;
		salt_len = 0;
		return 1;
	}
	strcpy(password, argv[1]);
	password[password_len] = '\0';
	memcpy(input, argv[2], input_len);
	memcpy(salt, argv[3], salt_len);
	iterations = atoi(argv[4]);
	ret = 1;
	output = NULL;
	
	/* *** protect buffers *** */
	ret = protect_buffer(&output, &output_len, input, input_len, password,
			     (unsigned char*) salt, salt_len, iterations);
	printf(">>> ret : %d\n", ret);
	print_hex(output, output_len, "OUTPUT");
	
	ret = 0;

cleanup:
	/* *** cleanup and return *** */
	memset(key, 0x00, 32);
	memset(password, 0x00, password_len);
	password_len = 0;
	free(password);
	memset(input, 0x00, input_len);
	input_len = 0;
	free(input);
	memset(salt, 0x00, salt_len);
	salt_len = 0;
	free(salt);
	iterations = 0;

	return ret;
}
