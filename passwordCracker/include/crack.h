#ifndef _CRACK_H_
#define _CRACK_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "utils.h"
#include "parser.h"
#include "md5.h"
#include "sha256.h"
#include "sha512.h"

#define BRUTE_FORCE_DEFAULT_LEN 4
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define SALT_LEN_MAX 16
#define ROUNDS_DEFAULT 5000
#define ROUNDS_MIN 1000
#define ROUNDS_MAX 999999999
#define MD5 1
#define SHA256 5
#define SHA512 6

static char itoa64[] = 
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/*
 * Modes available
 */
typedef enum {
    BRUTE_FORCE,
    DICO
} MODE;

/*
 * Informations about a user account
 */
typedef struct Account_ {
    char *login;
    int id; 
    int rounds;
    char *salt;
    char *hash;
} Account;

/*
 * Main function to crack all accounts in a shadow file
 */
void crack(const char *shadow, MODE mode, const char *dico,
           int bruteforceLen);

/*
 * Dictionary attack
 */
char* dictionaryAttack(Account *account, const char *dico);

/*
 * Brute-force attack
 */
char* bruteforceAttack(Account *account, int bruteforce_len);

void _crypt_to64(char *s, u_long v, int n);

void b64_from_24bit(uint8_t B2, uint8_t B1, uint8_t B0, int n,
                    int *buflen, char **cp);

#endif /* _CRACK_H_ */
