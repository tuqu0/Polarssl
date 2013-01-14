#include "../include/deriv_passwd.h"
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
	unsigned char key[32]; //SHA256 used
	char password[33];
	unsigned char salt[16];
	unsigned int iterations;

	/* *** check parameters *** */
	if (argc != 4) {
		fprintf(stderr, "usage : %s <password> <salt> <iterations>\n", argv[0]);
		return 1;
	}
	else if (strlen(argv[1]) > 32) {
		fprintf(stderr, "error : password too long (32 characters max)\n");
		return 1;
	}
	else if (strlen(argv[2]) > 16) { 
		fprintf(stderr, "error : salt too long (16 charachers max)\n");
		return 1;
	}
	else if (!atoi(argv[3]) || atoi(argv[3]) < 1) {
		fprintf(stderr, "error : number of iterations must be a positive integer\n");
		return 1;
	}

	/* *** initialization *** */
	memset(salt, 0x00, 16);
	memcpy(salt, argv[2], strlen(argv[2]));
	strcpy(password, argv[1]);
	password[strlen(argv[1])] = '\0';
	iterations = atoi(argv[3]);
	ret = 1;
	
	/* *** deriv password *** */
 	ret = deriv_passwd(key, password, salt, 16, iterations);
	if(ret != 0)
		goto cleanup;

	/* *** print the key *** */
	print_hex(key, 32, "key = ");
	
	ret = 0;

cleanup:
	/* *** cleanup and return *** */
	memset(key, 0x00, 32);
	memset(password, 0x00, 33);
	memset(salt, 0x00, 16);
	iterations = 0;

	return ret;
}
