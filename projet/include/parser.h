#ifndef _PARSER_H_
#define _PARSER_H_

#include "crack.h"

#define FIELD_PREFIX "$"
#define ROUNDS_PREFIX "rounds="

/*
 * Get accounts informations from the given shadow file
 */
struct Account_** readShadowFile(const char *shadow);

#endif /* _PARSER_H_ */
