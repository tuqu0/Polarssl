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

int main(int argc, char *argv[])

{
	int i;
	int ret;
	int salt_len;
	unsigned int hex;
	unsigned char key[32]; //SHA256 used
	char password[33];
	char salt[16];
	unsigned int iterations;
	unsigned char input[4096];
	int input_len;
	unsigned char *output;
	int output_len;

	/* *** check parameters *** */
	if (argc != 5) {
		fprintf(stderr, "usage : %s <password> <ciphered_text> <salt> <iterations>\n", argv[0]);
		return 1;
	}
	else if (strlen(argv[1]) > 32) {
		fprintf(stderr, "error : password too long (32 characters max)\n");
		return 1;
	}
	else if ((strlen(argv[2]) / 2) > 4095) {
		fprintf(stderr, "error : ciphered text too long (4095 characters max)\n");
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
	salt_len = strlen(argv[3]);
	strcpy(salt, argv[3]);
	strcpy(password, argv[1]);
	password[strlen(argv[1])] = '\0';
	input_len = strlen(argv[2]) / 2;
	for (i = 0; i < input_len && sscanf(argv[2], "%02X", &hex) == 1; i++) {
		input[i] = (unsigned char) hex;
		printf("input %c\n", input[i]);
	}
	input[input_len] = '\0';
	iterations = atoi(argv[4]);
	ret = 1;
	output = NULL;
	
	/* *** protect buffers *** */
	ret = unprotect_buffer(&output, &output_len, input, input_len, password,
			     (unsigned char*) salt, salt_len, iterations);
	printf(">>> ret : %d\n", ret);
	print_hex(output, output_len, "OUTPUT");
	
	ret = 0;
cleanup:
	/* *** cleanup and return *** */
	memset(key, 0x00, 32);
	memset(password, 0x00, 33);
	memset(input, 0x00, 4096);
	memset(salt, 0x00, 16);
	iterations = 0;

	return ret;
}
