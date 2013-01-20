#ifndef _MD5_H_
#define _MD5_H_

#include <stdio.h>

/*
 * Hash a word with given salt and number of rounds, then
 * returns the hash
 */
char* cipher_md5(char *word, char *salt, int rounds);

#endif /* _MD5_H_ */
