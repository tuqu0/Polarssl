#ifndef _CRACK_H_
#define _CRACK_H_

 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>

 #include "utils.h"

 #define FIELD_PREFIX "$"
 #define ROUNDS_PREFIX "rounds="
 #define ROUNDS_DEFAULT 5000
 #define ROUNDS_MIN 1000
 #define ROUNDS_MAX 999999999
 #define SHA512 6
 #define SHA256 5
 #define MD5 1

 /*
 * Informations abount a user account
 */
 typedef struct {
    char *login;
    int id; 
    int rounds;
    char *salt;
    char *hash;
 } Account;

 /*
 * Main function to crack all accounts in a shadow file
 */
 void crack(const char *shadow, MODE mode, const char *dico);

 /*
 * Get accounts informations from the given shadow file
 */
 Account** readShadowFile(const char *shadow);

 /*
 * Free the array of "ACCOUNT" elements
 */
 void freeAccounts(Account **array);

#endif /* _CRACK_H_ */
