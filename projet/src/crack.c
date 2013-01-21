#include "../include/crack.h"

void crack(const char *shadow, MODE mode, const char *dico,
        int bruteforceLen)
{
    int i, nb;
    Account **accounts = NULL;
    Account *account = NULL;

    /* *** Get accounts informations from shadow file *** */
    accounts = readShadowFile(shadow);
    if (accounts == NULL)
    {
        fprintf(stderr, "error : no valid account found\n");
        return;     
    }

    /* *** Launch attack *** */
    if (mode == DICO)
        dictionaryAttack(accounts, dico);
    else
        bruteforceAttack(accounts, bruteforceLen);

    /* *** Display results for each account *** */
    nb = AccountsLen(accounts);
    for (i = 0; i < nb; i++)
    {
        account = accounts[i];

        printf("\n**************************************************"\
                "******************\n");
        printf("login    : %s\n", account->login);
        switch(account->id)
        {
            case MD5:
                printf("type     : MD5\n");
                break;
            case SHA256:
                printf("type     : SHA-256\n");
                break;
            case SHA512:
                printf("type     : SHA-512\n");
                break;
        }
        printf("salt     : %s\n", account->salt);
        printf("rounds   : %d\n", account->rounds);
        printf("login    : %s\n", account->login);
        if (account->password != NULL)
            printf("password : %s\n", account->password);
        else
            printf("password not found\n");
    }

    /* *** Restore memory *** */
    freeAccounts(accounts);
}

void dictionaryAttack(Account **accounts, const char *dico)
{
    int i, nb, found;
    size_t read, len;
    char *line = NULL;
    char *word = NULL;
    char *hash = NULL;
    FILE *f = NULL;
    Account *account = NULL;

    /* *** Init *** */
    nb = AccountsLen(accounts);
    found = 0;

    /* *** Check parameters *** */
    if (accounts == NULL || dico == NULL)
        goto exit;

    /* *** Try to open the dictionary *** */
    f = fopen(dico, "r");
    if (f == NULL)
    {
        fprintf(stderr, "error : unable to open %s\n", dico);
        goto exit;
    }

    /* *** Try each word in the dictionary *** */
    while ((read = getline(&line, &len, f)) != EOF)
    {
        /* *** If all accounts have been cracked *** */
        if (found == nb)
            goto exit;

        word = strtok(line, "\r\n");
        if (word == NULL)
            continue;

        /* *** Print the word *** */
        printf(" %s\n", word);

        /* *** Try the word for each account *** */
        for (i = 0; i < nb; i++)
        {
            account = accounts[i];
            switch(account->id)
            {
                case MD5:
                    hash = crypt_md5(word, account->salt, account->rounds);
                    break;
                case SHA256:
                    hash = crypt_sha256(word, account->salt,
                            account->rounds);
                    break;
                case SHA512:
                    hash = crypt_sha512(word, account->salt,
                            account->rounds);
                    break;
            }

            /* *** Check if the hash is identical *** */
            if (hash != NULL)
            {
                if (account->password == NULL && 
                        !strcmp(account->hash, hash))
                {
                    printf("\nlogin    : %s\n", account->login);
                    printf("password : %s\n", word);
                    account->password = (char *) malloc(strlen(word) + 1);
                    if (account->password == NULL)
                    {
                        fprintf(stderr, "error : memory allocation "\
                                "failed\n");
                        goto exit;
                    }
                    strcpy(account->password, word);
                    memset(account->password + strlen(word), '\0', 1);
                    found++;
                    getchar();
                }
                free(hash);
            }
        }

        /* *** Restore memory *** */
        free(line);
        line = NULL;
        word = NULL;
        hash = NULL;
    }

exit:
    if (f != NULL)
        fclose(f);
    if (line != NULL)
        free(line);
    if (hash != NULL)
        free(hash);
}

void bruteforceAttack(Account **accounts, int max_len)
{
    int i, j, k, nb, found;
    char *word = NULL;
    char *hash = NULL;
    Account *account = NULL;

    /* *** Check parameters *** */
    if (accounts == NULL)
        goto exit;
    if (max_len < 1)
        max_len = BRUTE_FORCE_DEFAULT_LEN;

    /* *** Init *** */
    nb = AccountsLen(accounts);
    found = 0;

    word = malloc((max_len + 1) * sizeof(char));
    if (word == NULL)
    {
        fprintf(stderr, "error : memory allocation failed\n");
        goto exit;
    }

    for (i = 1; i <= max_len; i++)
    {
        for (j = 0; j < i; j++)
            word[j]='a';
        word[i]=0;
    
        do
        {
            /* *** If all accounts have been cracked *** */
            if (found == nb)
                goto exit;

            /* *** Display the testing word *** */
            printf(" %s\n", word);

            /* *** Try the word for each account *** */
            for (k = 0; k < nb; k++)
            {
                account = accounts[k];

                /* *** Get the hash of the word *** */
                switch(account->id)
                {
                    case MD5:
                        hash = crypt_md5(word, account->salt,
                                account->rounds);
                        break;
                    case SHA256:
                        hash = crypt_sha256(word, account->salt,
                                account->rounds);
                        break;
                    case SHA512:
                        hash = crypt_sha512(word, account->salt,
                                account->rounds);
                        break;
                }   

                /* *** Check if the word hash is identical *** */
                if (hash != NULL)
                {
                    if (account->password == NULL && 
                        !strcmp(account->hash, hash))
                    {
                        printf("\nlogin    : %s\n", account->login);
                        printf("password : %s\n", word);
                        account->password = (char *) malloc(strlen(word)
                                                             + 1);
                        if (account->password == NULL)
                            fprintf(stderr, "error : memory allocation "\
                                    "failed\n");
                        memset(account->password + strlen(word), '\0', 1);
                        getchar();
                        found++;
                    }
                    free(hash);
                    hash = NULL;
                }
            }
        } while (inc(word));
    }

    /* *** Restore memory *** */
    free(word);
    word = NULL;

exit:
    if (hash != NULL)
        free(hash);
    return ;
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

int AccountsLen(Account **array)
{
    int accounts_len;

    accounts_len = 0;
    while (array[accounts_len] != NULL)
        accounts_len++;

    return accounts_len;
}

void freeAccounts(Account **array)
{
    int i, nb;
    Account *it;

    /* *** Check parameters *** */
    if (array == NULL)
        return;

    /* *** Get array length *** */
    nb = AccountsLen(array);

    /* *** Free each element *** */
    for (i = 0; i < nb; i++)
    {
        it = array[i];
        if (it->login != NULL)
            free(it->login);
        if (it->salt != NULL)
            free(it->salt);
        if (it->hash != NULL)
            free(it->hash);
        if (it->password != NULL)
            free(it->password);
        free(it);           
    }
    free(array);
}
