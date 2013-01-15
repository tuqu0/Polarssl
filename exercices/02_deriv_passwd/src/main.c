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
	int ret, password_len, salt_len;
	unsigned char key[32]; //SHA256 used
	unsigned int iterations;
	char *password;
	unsigned char *salt;

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
	password_len = strlen(argv[1]);
	password = (char *) malloc(sizeof(char) * (password_len + 1));
	salt_len = strlen(argv[2]);
	salt = (unsigned char *) malloc(sizeof(unsigned char) * salt_len);
	if (password == NULL || salt == NULL) {
		fprintf(stderr, "error : memory allocation fails\n");
		password_len = 0;
		salt_len = 0;
		return 1;
	}
	strcpy(password, argv[1]);
	password[password_len] = '\0';
	memcpy(salt, argv[2], salt_len);
	iterations = atoi(argv[3]);
	ret = 1;
	
	/* *** deriv password *** */
 	ret = deriv_passwd(key, password, salt, salt_len, iterations);
	if(ret != 0)
		goto cleanup;

	/* *** print the key *** */
	print_hex(key, 32, "key = ");
	
	ret = 0;

cleanup:
	/* *** cleanup and return *** */
	memset(key, 0x00, 32);
	memset(password, 0x00, password_len);
	password_len = 0;
	free(password);
	memset(salt, 0x00, salt_len);
	salt_len = 0;
	free(salt);
	iterations = 0;

	return ret;
}
