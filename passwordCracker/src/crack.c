#include "../include/crack.h"

void crack(const char *shadow, MODE mode, const char *dico,
        int bruteforceLen)
{
    int i, accounts_len;
    char *password;
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

        /* *** Display informations about the current account *** */
        printf("**************************************************\
******************\n");
        printf("account : %s\n", account->login);
        switch(account->id)
        {
            case MD5:
                printf("type    : MD5\n");
                break;
            case SHA256:
                printf("type    : SHA-256\n");
                break;
            case SHA512:
                printf("type    : SHA-512\n");
                break;
        }
        printf("salt    : %s\n", account->salt);
        printf("rounds  : %d\n", account->rounds);
        printf("words   :\n");

        /* *** Launch attack *** */
        password = NULL;
        if (mode == DICO)
            password = dictionaryAttack(account, dico);
        else
            password = bruteforceAttack(account, bruteforceLen);

        /* *** Check results *** */
        if (password != NULL)
        {
            printf("\n>>>>>>>>>> Paswword found ! :) <<<<<<<<<<\n");
            printf("login    : %s\n", account->login);
            printf("password : %s\n", password);
            free(password);
            getchar();
        }
    }

    /* *** Restore memory *** */
    freeAccounts(accounts);
}

char* dictionaryAttack(Account *account, const char *dico)
{
    size_t read, len;
    char *line, *token, *word, *hash_word;
    FILE *f;

    /* *** Init *** */
    read = 0;
    len = 0;
    line = NULL;
    token = NULL;
    word = NULL;
    hash_word = NULL;
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

    /* *** Try each word in the dictionary *** */
    while ((read = getline(&line, &len, f)) != EOF)
    {
        token = strtok(line, "\r\n");
        if (token == NULL)
            continue;
        else
        {
            word = (char *) malloc(strlen(token) + 1);
            if (word == NULL)
            {
                fprintf(stderr, "error : memory allocation failed\n");
                goto exit;
            }
            strcpy(word, token);
            word[strlen(token)] = '\0';
        }

        /* *** Display the testing word *** */
        printf("           %s\n", word);

        /* *** Hash the word with account algorithm, salt and rounds *** */
        switch(account->id)
        {
            case MD5:
                hash_word = crypt_md5(word, account->salt,
                        account->rounds);
                break;
            case SHA256:
                hash_word = crypt_sha256(word, account->salt,
                        account->rounds);
                break;
            case SHA512:
                hash_word = crypt_sha512(word, account->salt,
                        account->rounds);
                break;
        }

        /* *** Check if the word hash matches with password hash *** */
        if (hash_word != NULL)
        {
            if (!strcmp(account->hash, hash_word))
            {
                free(hash_word);
                free(line);
                goto exit;
            }
            free(hash_word);
        }

        /* *** Restore memory *** */
        free(word);
        free(line);
        line = NULL;
        token = NULL;
        word = NULL;
        hash_word = NULL;
    }

exit:
    if (f != NULL)
        fclose(f);
    return word;
}

char* bruteforceAttack(Account *account, int max_len)
{
    int i,j;
    char *word, *hash_word;

    /* *** Check parameters *** */
    if (max_len < 1)
        max_len = BRUTE_FORCE_DEFAULT_LEN;

    word = malloc((max_len + 1) * sizeof(char));
    if (word == NULL)
    {
        fprintf(stderr, "error : memory allocation failed\n");
        return;
    }

    for (i = 1; i <= max_len; i++)
    {
        for (j = 0; j < i; j++)
            word[j]='a';
        word[i]=0;

        do
        {
            /* *** Display the testing word *** */
            printf("           %s\n", word);

            /* *** Get the hash of the word *** */
            hash_word = NULL;
            switch(account->id)
            {
                case MD5:
                    hash_word = crypt_md5(word, account->salt,
                            account->rounds);
                    break;
                case SHA256:
                    hash_word = crypt_sha256(word, account->salt,
                            account->rounds);
                    break;
                case SHA512:
                    hash_word = crypt_sha512(word, account->salt,
                            account->rounds);
                    break;
            }

            /* *** Check if the word hash matches with password hash *** */
            if (hash_word != NULL)
            {
                if (!strcmp(account->hash, hash_word))
                {
                    free(hash_word);
                    goto exit;
                }
                free(hash_word);
            }
        } while (inc(word));
    }

    /* *** Restore memory *** */
    free(word);
    word = NULL;

exit:
    return word;
}

int inc(char *c)
{
    if (c[0] == 0)
        return 0;

    if (c[0] == 'z')
    {
        c[0] = 'a';
        return inc(c + sizeof(char));
    }   
    c[0]++;

    return 1;
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
