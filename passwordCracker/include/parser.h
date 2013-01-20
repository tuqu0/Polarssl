#ifndef _PARSER_H_
#define _PARSER_H_

#include "crack.h"

#define FIELD_PREFIX "$"
#define ROUNDS_PREFIX "rounds="

/*
 * Get accounts informations from the given shadow file
 */
struct Account_** readShadowFile(const char *shadow);

/*
 * Return the number of "Account" elements
 */
int AccountsLen(struct Account_ **array);

/*
 * Free the array of "Account" elements
 */
void freeAccounts(struct Account_ **array);

#endif /* _PARSER_H_ */
