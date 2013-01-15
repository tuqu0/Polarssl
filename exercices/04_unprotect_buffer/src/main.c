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
	int c, i, ret, f_len, output_len;
	unsigned int iterations; 
	unsigned char key[32]; //SHA256 used
	char password[33];
	char salt[16];
	unsigned char *output;
	unsigned char *input;
	FILE *f;

	/* *** check parameters *** */
	if (argc != 5) {
		fprintf(stderr, "usage : %s <password> <ciphered_text_file> <salt> \
<iterations>\n", argv[0]);
		return 1;
	}
	else if (strlen(argv[1]) > 32) {
		fprintf(stderr, "error : password too long (32 characters max)\n");
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
	strcpy(password, argv[1]);
	password[strlen(argv[1])] = '\0';
	memset(salt, 0x00, 16);
	memcpy(salt, argv[3], strlen(argv[3]));
	iterations = atoi(argv[4]);
	ret = 1;
	output = NULL;
	f = NULL;

	/* *** read ciphered text from given file *** */
	if ((f = fopen(argv[2], "r")) == 0) {
		fprintf(stderr, "file not found\n");
		goto cleanup;
	}
	fseek(f, 0, SEEK_END);
	f_len = ftell(f);
	input = (unsigned char *) malloc(sizeof(unsigned char) * f_len);
	if (input == NULL)
		goto cleanup;
	i = 0;
	while(fscanf(f, "%02X", &c) > 0 && i < f_len)
		input[i++] = (unsigned char) c;

	/* *** protect buffers *** */
	ret = unprotect_buffer(&output, &output_len, input, f_len / 2, password,
			     (unsigned char*) salt, 16, iterations);
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
	memset(password, 0x00, 33);
	memset(salt, 0x00, 16);
	iterations = 0;

	return ret;
}
