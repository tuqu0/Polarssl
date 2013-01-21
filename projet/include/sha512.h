#ifndef _SHA512_H_
#define _SHA512_H_

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>

#include "polarssl/sha4.h"
#include "crack.h"

#define OUTPUT_SHA512_LEN 86

/*
 * Hash a word with given salt and number of rounds, then
 * returns the hash
 */
char* crypt_sha512(const char *key, const char *salt, size_t rounds);


char* crypt_sha512_r(const char *key, const char *salt, size_t rounds,
                     char *buffer, int buflen);

#endif /* _SHA512_H_ */
