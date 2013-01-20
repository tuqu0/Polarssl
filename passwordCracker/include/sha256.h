#ifndef _SHA256_H_
#define _SHA256_H_

#include <stdio.h>

/*
 * Hash a word with given salt and number of rounds, then
 * returns the hash
 */
char* cipher_sha256(char *word, char *salt, int rounds);

#endif /* _SHA256_H_ */
