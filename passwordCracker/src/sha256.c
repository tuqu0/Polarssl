#include "../include/sha256.h"

char* crypt_sha256(const char *key, const char *salt, size_t rounds)
{
    char *buffer;

    buffer = (char *) malloc(OUTPUT_SHA256_LEN + 1);
    if (buffer == NULL)
    {
        fprintf(stderr, "error : memory allocation failed\n");
        return NULL;
    }

    return crypt_sha256_r(key, salt, rounds, buffer, OUTPUT_SHA256_LEN + 1);
}

char* crypt_sha256_r(const char *key, const char *salt, size_t rounds, char *buffer, int buflen)
{
	uint8_t alt_result[32], temp_result[32];
	sha2_context ctx, alt_ctx;
	size_t salt_len, key_len, cnt;
	char *cp, *copied_key, *copied_salt, *p_bytes, *s_bytes;

	copied_key = NULL;
	copied_salt = NULL;

	salt_len = MIN(strcspn(salt, "$"), SALT_LEN_MAX);
	key_len = strlen(key);

	/* Prepare for the real work. */
	sha2_starts(&ctx, 0);

	/* Add the key string. */
	sha2_update(&ctx, (unsigned char *)key, key_len);

	/* The last part is the salt string. This must be at most 8
	 * characters and it ends at the first `$' character (for
	 * compatibility with existing implementations). */
	sha2_update(&ctx, (unsigned char*)salt, salt_len);

	/* Compute alternate SHA256 sum with input KEY, SALT, and KEY. The
	 * final result will be added to the first context. */
	sha2_starts(&alt_ctx, 0);

	/* Add key. */
	sha2_update(&alt_ctx, (unsigned char*)key, key_len);

	/* Add salt. */
	sha2_update(&alt_ctx, (unsigned char*)salt, salt_len);

	/* Add key again. */
	sha2_update(&alt_ctx, (unsigned char*)key, key_len);

	/* Now get result of this (32 bytes) and add it to the other context. */
	sha2_finish(&alt_ctx, alt_result);

	/* Add for any character in the key one byte of the alternate sum. */
	for (cnt = key_len; cnt > 32; cnt -= 32)
		sha2_update(&ctx, (unsigned char*)alt_result, 32);
	sha2_update(&ctx, (unsigned char*)alt_result, cnt);

	/* Take the binary representation of the length of the key and for
	 * every 1 add the alternate sum, for every 0 the key. */
	for (cnt = key_len; cnt > 0; cnt >>= 1)
		if ((cnt & 1) != 0)
			sha2_update(&ctx, (unsigned char*)alt_result, 32);
		else
			sha2_update(&ctx, (unsigned char*)key, key_len);

	/* Create intermediate result. */
	sha2_finish(&ctx, alt_result);

	/* Start computation of P byte sequence. */
	sha2_starts(&alt_ctx, 0);

	/* For every character in the password add the entire password. */
	for (cnt = 0; cnt < key_len; ++cnt)
		sha2_update(&alt_ctx, (unsigned char*)key, key_len);

	/* Finish the digest. */
	sha2_finish(&alt_ctx, temp_result);

	/* Create byte sequence P. */
	cp = p_bytes = alloca(key_len);
	for (cnt = key_len; cnt >= 32; cnt -= 32) {
		memcpy(cp, temp_result, 32);
		cp += 32;
	}
	memcpy(cp, temp_result, cnt);

	/* Start computation of S byte sequence. */
	sha2_starts(&alt_ctx, 0);

	/* For every character in the password add the entire password. */
	for (cnt = 0; cnt < 16 + alt_result[0]; ++cnt)
		sha2_update(&alt_ctx, (unsigned char*)salt, salt_len);

	/* Finish the digest. */
	sha2_finish(&alt_ctx, temp_result);

	/* Create byte sequence S. */
	cp = s_bytes = alloca(salt_len);
	for (cnt = salt_len; cnt >= 32; cnt -= 32) {
		memcpy(cp, temp_result, 32);
		cp += 32;
	}
	memcpy(cp, temp_result, cnt);

	/* Repeatedly run the collected hash value through SHA256 to burn CPU
	 * cycles. */
	for (cnt = 0; cnt < rounds; ++cnt) {
		/* New context. */
		sha2_starts(&ctx, 0);

		/* Add key or last result. */
		if ((cnt & 1) != 0)
			sha2_update(&ctx, (unsigned char*)p_bytes, key_len);
		else
			sha2_update(&ctx, (unsigned char*)alt_result, 32);

		/* Add salt for numbers not divisible by 3. */
		if (cnt % 3 != 0)
			sha2_update(&ctx, (unsigned char*)s_bytes, salt_len);

		/* Add key for numbers not divisible by 7. */
		if (cnt % 7 != 0)
			sha2_update(&ctx, (unsigned char*)p_bytes, key_len);

		/* Add key or last result. */
		if ((cnt & 1) != 0)
			sha2_update(&ctx, (unsigned char*)alt_result, 32);
		else
			sha2_update(&ctx, (unsigned char*)p_bytes, key_len);

		/* Create intermediate result. */
		sha2_finish(&ctx, alt_result);
	}

	cp = buffer;
	b64_from_24bit(alt_result[0], alt_result[10], alt_result[20], 4, &buflen, &cp);
	b64_from_24bit(alt_result[21], alt_result[1], alt_result[11], 4, &buflen, &cp);
	b64_from_24bit(alt_result[12], alt_result[22], alt_result[2], 4, &buflen, &cp);
	b64_from_24bit(alt_result[3], alt_result[13], alt_result[23], 4, &buflen, &cp);
	b64_from_24bit(alt_result[24], alt_result[4], alt_result[14], 4, &buflen, &cp);
	b64_from_24bit(alt_result[15], alt_result[25], alt_result[5], 4, &buflen, &cp);
	b64_from_24bit(alt_result[6], alt_result[16], alt_result[26], 4, &buflen, &cp);
	b64_from_24bit(alt_result[27], alt_result[7], alt_result[17], 4, &buflen, &cp);
	b64_from_24bit(alt_result[18], alt_result[28], alt_result[8], 4, &buflen, &cp);
	b64_from_24bit(alt_result[9], alt_result[19], alt_result[29], 4, &buflen, &cp);
	b64_from_24bit(0, alt_result[31], alt_result[30], 3, &buflen, &cp);
	if (buflen <= 0) {
		errno = ERANGE;
		buffer = NULL;
	}
	else
		*cp = '\0';

	return buffer;
}
