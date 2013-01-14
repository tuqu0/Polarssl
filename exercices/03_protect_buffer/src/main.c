#include "../include/deriv_passwd.h"
#include "../include/protect_buffer.h"
#include "../include/gen_key.h"
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
	int ret;
	int salt_len;
	unsigned char key[32]; //SHA256 used
	char password[33];
	char salt[17];
	unsigned int iterations;
	unsigned char input[4096];
	int input_len;
	unsigned char *output;
	int output_len;

	/* *** check parameters *** */
	if (argc != 5) {
		fprintf(stderr, "usage : %s <password> <plain_text> <salt_len> <iterations>\n", argv[0]);
		return 1;
	}
	else if (strlen(argv[1]) > 32) {
		fprintf(stderr, "error : password too long (32 characters max)\n");
		return 1;
	}
	else if (strlen(argv[2]) > 4095) {
		fprintf(stderr, "error : plain text too long (4095 characters max)\n");
		return 1;
	}
	else if (!atoi(argv[3]) || atoi(argv[3]) < 1 || atoi(argv[3]) > 16) {
		fprintf(stderr, "error : salt len must be a positive integer less or equal than 16\n");
		return 1;
	}
	else if (!atoi(argv[4]) || atoi(argv[4]) < 1) {
		fprintf(stderr, "error : number of iterations must be a positive integer\n");
		return 1;
	}

	/* *** initialization *** */
	salt_len = atoi(argv[3]);
	ret = gen_key(salt, salt_len);
	if (ret == 1) {
		fprintf(stderr, "unable to generate a salt\n");
		goto cleanup;
	}
	salt[salt_len] = '\0';
	strcpy(password, argv[1]);
	password[strlen(argv[1])] = '\0';
	input_len = strlen(argv[2]);
	strcpy(input, argv[2]);
	input[input_len] = '\0';
	iterations = atoi(argv[4]);
	ret = 1;
	output = NULL;
	
	/* *** protect buffers *** */
	ret = protect_buffer(&output, &output_len, input, input_len, password,
			     (unsigned char*) salt, strlen(salt), iterations);
	print_hex(salt, salt_len, "salt = ");
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
