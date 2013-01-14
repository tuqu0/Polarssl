#include "../include/deriv_passwd.h"
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

int main(int argc, char **argv)
{
	int ret;
	int salt_len;	
	unsigned char key[32]; //SHA256 used
	char password[32];
	unsigned char salt[17];
	unsigned int iterations;

	/* *** check parameters *** */
	if (argc != 4) {
		fprintf(stderr, "usage : %s <password> <salt_len> <iterations>\n", argv[0]);
		return 1;
	}
	else if (strlen(argv[1]) > 32) {
		fprintf(stderr, "error : password too long (32 characters max)\n");
		return 1;
	}
	else if (!atoi(argv[2]) || atoi(argv[2]) < 1 
		 || atoi(argv[2]) > 16) {
		fprintf(stderr, "error : salt len must be a positive integer less or equal than 16\n");
		return 1;
	}
	else if (!atoi(argv[3]) || atoi(argv[3]) < 1) {
		fprintf(stderr, "error : number of iterations must be a positive integer\n");
		return 1;
	}

	/* *** initialization *** */
	salt_len = atoi(argv[2]);
	ret = gen_key(salt, salt_len);
	if (ret == 1) {
		fprintf(stderr, "error : unable to generate a salt\n");
		return 1;
	}
	salt[salt_len] = '\0';
	strcpy(password, argv[1]);
	iterations = atoi(argv[3]);
	ret = 1;
	
	/* *** deriv password *** */
 	ret = deriv_passwd(key, password, salt, salt_len, iterations);
	if(ret != 0)
		goto cleanup;

	/* *** print the salt *** */
	print_hex(salt, salt_len, "salt = ");
	
	/* *** print the key *** */
	print_hex(key, 32, "key = ");
	
	ret = 0;

cleanup:
	/* *** cleanup and return *** */
	memset(key, 0x00, 32);
	memset(password, 0x00, 32);
	memset(salt, 0x00, 17);
	iterations = 0;

	return ret;
}
