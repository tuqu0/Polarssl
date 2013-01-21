#ifndef _MD5_H_
#define _MD5_H_

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "polarssl/md5.h"
#include "crack.h"

#define MD5_SIZE 16

/*
 * Hash a word with given salt and number of rounds, then
 * returns the hash
 */
char* crypt_md5(const char *pw, const char *salt, size_t rounds);

#endif /* _MD5_H_ */

