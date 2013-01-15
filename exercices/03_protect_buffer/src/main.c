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
	int ret, password_len, output_len;
	unsigned char key[32]; //SHA256 used
	unsigned char salt[16];
	unsigned char input[128];
	unsigned int iterations;
	char *password = NULL;
	unsigned char *output = NULL;

	/* *** check parameters *** */
	if (argc != 2) {
		fprintf(stderr, "usage : %s <password>\n", argv[0]);
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
	memset(input, 0x12, 128); // input = 0x12 ... 0x12
	memset(salt, 0x00, 16); // salt = 0x00 ... 0x00
	iterations = 1<<5; //32
	ret = 1;
	output = NULL;
	
	/* *** protect buffers *** */
	ret = protect_buffer(&output, &output_len, input, 128, password,
			     salt, 16, iterations);
	printf(">>> ret : %d\n", ret);
	print_hex(output, output_len, "OUTPUT");
	
	ret = 0;

cleanup:
	/* *** cleanup and return *** */
	memset(key, 0x00, 32);
	memset(password, 0x00, password_len);
	password_len = 0;
	free(password);
	memset(input, 0x00, 128);
	memset(salt, 0x00, 16);
	iterations = 0;

	return ret;
}
