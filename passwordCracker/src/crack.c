#include "../include/crack.h"

void crack(const char *shadow, MODE mode, const char *dico)
{
    int i, accounts_len;
    Account **accounts;
    Account *account;

    /* *** Get accounts informations from shadow file *** */
    accounts = readShadowFile(shadow);
    if (accounts == NULL)
    {
        fprintf(stderr, "error : no valid account found\n");
        return;     
    }

    /* *** Crack each account *** */
    accounts_len = AccountsLen(accounts);
    for (i = 0; i < accounts_len; i++)
    {
        account = accounts[i];

        if (mode == DICO)
            dictionaryAttack(account, dico);
        else
            bruteforceAttack(account);
    }

    /* *** Restore memory *** */
    freeAccounts(accounts);
}

char* dictionaryAttack(Account *account, const char *dico)
{
    size_t read, len;
    char *word, *line, *password, *hash_word;
    FILE *f;

    /* *** Init *** */
    read = 0;
    len = 0;
    line = NULL;
    word = NULL;
    hash_word = NULL;
    password = NULL;
    f = NULL;

    /* *** Check parameters *** */
    if (dico == NULL)
        goto exit;

    f = fopen(dico, "r");
    if (f == NULL)
    {
        fprintf(stderr, "error : unable to open %s\n", dico);
        goto exit;
    }

    /* *** Display informations about the current account *** */
    printf("################################\n");
    printf("account : %s\n", account->login);
    printf("id      : %d\n", account->id);
    printf("rounds  : %d\n", account->rounds);
    printf("words   :\n");

    /* *** Try each word in the dictionary *** */
    while ((read = getline(&line, &len, f)) != EOF)
    {
        word = strtok(line, "\r\n");
        /* *** Display the testing word *** */
        printf("         %s\n", word);

        /* *** Hash the word with account algorithm, salt and rounds  *** */
        switch(account->id)
        {
            case MD5:
                hash_word = cipher_md5(word, account->salt,
                        account->rounds);
            case SHA256:
                hash_word = cipher_sha256(word, account->salt,
                        account->rounds);
            case SHA512:
                hash_word = crypt_sha512(word, account->salt,
                        account->rounds);
        }

        /* *** Check if the word hash matches with password hash *** */
        if (hash_word != NULL)
        {
            if (!strcmp(account->hash, hash_word))
            {
                printf("\n---------------------------\n");
                printf("Password found !\n");
                printf("login    : %s\n", account->login);
                printf("password : %s\n", word);
                printf("---------------------------\n");
                getchar();
                free(hash_word);
                goto exit;
            }
            free(hash_word);
        }

        /* *** Restore memory *** */
        free(line);
        line = NULL;
        word = NULL;
        hash_word = NULL;
    }

exit:
    if (f != NULL)
        fclose(f);
    if (line != NULL)
        free(line);
    return password;
}

char* bruteforceAttack(Account *account)
{
    char *password;

    /* *** Init *** */
    password = NULL;

    printf("Brute force attack not implemented yet\n");

exit: 
    return password;
}

void _crypt_to64(char *s, u_long v, int n)
{
    while (--n >= 0) {
        *s++ = itoa64[v&0x3f];
        v >>= 6;
    }
}

void b64_from_24bit(uint8_t B2, uint8_t B1, uint8_t B0, int n,
                    int *buflen, char **cp)
{
    uint32_t w;
    int i;

    w = (B2 << 16) | (B1 << 8) | B0;
    for (i = 0; i < n; i++) {
        **cp = itoa64[w&0x3f];
        (*cp)++;
        if ((*buflen)-- < 0)
            break;
        w >>= 6;
    }
}
