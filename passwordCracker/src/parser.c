#include "../include/parser.h"

Account** readShadowFile(const char *shadow)
{
    int cpt, id, rounds, login_len, salt_len, hash_len;
    size_t read, len;
    char *line, *line_saved, *token, *login, *salt, *hash;
    FILE *f;
    Account *account;
    Account **accounts;

    /* *** Init *** */
    cpt = 0;
    read = 0;
    len = 0;
    line = NULL;
    account = NULL;
    accounts = NULL;
    f = NULL;

    /* *** Read shadow file *** */
    f = fopen(shadow, "r");
    if (f == NULL)
    {
        fprintf(stderr, "error : unable to open %s\n", shadow);
        goto exit;
    }
    while ((read = getline(&line, &len, f)) != EOF)
    {
        /* *** Init *** */
        line_saved = NULL;
        token = NULL;
        login = NULL;
        salt = NULL;
        hash = NULL;
        id = 0;
        rounds = 0;
        login_len = 0;
        salt_len = 0;
        hash_len = 0;

        /* *** Copy the current line *** */
        line_saved = (char *) malloc(strlen(line) + 1);
        if (line_saved == NULL)
        {
            fprintf(stderr, "error : memory allocation failed\n");
            goto exit;
        }
        strcpy(line_saved, line);
        line_saved[strlen(line)] = '\0';

        /* *** Parsing *** */
        token = strtok(line, FIELD_PREFIX);
        if (strcmp(line_saved, token))
        {
            /* *** login *** */
            login_len = strlen(token) - 1; 
            login = (char *) malloc(login_len + 1);
            if (login == NULL)
            {
                fprintf(stderr, "error : memory allocation failed\n");
                goto exit;
            }
            strncpy(login, token, login_len);
            login[login_len] = '\0';

            /* *** algorithm *** */
            token = strtok(NULL, FIELD_PREFIX);
            if (token  == NULL)
            {
                fprintf(stderr, "error : invalid file format\n");
                goto exit;
            }
            if ((id = atoi(token)) == 0
                    || (id != SHA512 && id != SHA256 && id != MD5))
            {
                fprintf(stderr, "error : invalid algorithm id\n");
                goto exit;
            }

            /* *** rounds ? *** */
            if (strstr(line_saved, ROUNDS_PREFIX))
            {
                token = strtok(NULL, FIELD_PREFIX);
                if (token == NULL)
                {
                    fprintf(stderr, "error : invalid file format\n");
                    goto exit;
                }
                token = strdup(token + strlen(ROUNDS_PREFIX));
                if (token == NULL)
                {
                    fprintf(stderr, "error : memory allocation failed\n");
                    goto exit;
                }
                if ((rounds = atoi(token)) == 0
                        || (rounds < ROUNDS_MIN || rounds > ROUNDS_MAX))
                {
                    fprintf(stderr, "error : invalid rounds number\n");
                    free(token);
                    goto exit;
                }
                free(token); 
            }
            else if (id == MD5)
                rounds = ROUNDS_MIN;
            else
                rounds = ROUNDS_DEFAULT;

            /* *** salt *** */
            token = strtok(NULL, FIELD_PREFIX);
            if (token == NULL)
            {
                fprintf(stderr, "error : invalid file format\n");
                goto exit;
            }
            salt_len = strlen(token);
            if (salt_len > SALT_LEN_MAX)
            {
                fprintf(stderr, "error : salt too long\n");
                goto exit;
            }
            salt = (char *) malloc(salt_len + 1);
            if (salt == NULL)
            {
                fprintf(stderr, "error : memory allocation failed\n");
                goto exit;
            }
            strcpy(salt, token);
            salt[salt_len] = '\0';

            /* *** hash *** */
            token = strtok(NULL, ":");
            if (token == NULL)
            {
                fprintf(stderr, "error : invalid file format\n");
                goto exit;
            }
            hash_len = strlen(token);
            hash = (char *) malloc(hash_len + 1);
            if (hash == NULL)
            {
                fprintf(stderr, "error : memory allocation failed\n");
                goto exit;
            }
            strcpy(hash, token);
            hash[hash_len] = '\0';

            /* *** Store informations about the current account *** */
            account = (Account *) malloc(sizeof(Account));
            if (account == NULL)
            {
                fprintf(stderr, "error : memory allocation failed\n");
                goto exit;
            }
            account->login = login;
            account->salt = salt;
            account->hash = hash;
            account->id = id;
            account->rounds = rounds;
            accounts = (Account **) realloc(accounts, (cpt + 1) *
                    sizeof(Account));
            if (accounts == NULL)
            {
                fprintf(stderr, "error : memory allocation failed\n");
                goto exit;
            }
            accounts[cpt] = account;
            cpt++;
        }

        /* *** Restore memory *** */
        free(line_saved);
        free(line);
        line_saved = NULL;       
        line = NULL;
    }

exit:
    if (accounts != NULL)
        accounts[cpt] = NULL;
    if (f != NULL)
        fclose(f);
    if (line != NULL)
        free(line);
    if (line_saved != NULL)
        free(line_saved);
    return accounts;
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
    int i, len;
    Account *it;

    /* *** Check parameters *** */
    if (array == NULL)
        return;

    /* *** Get array length *** */
    len = AccountsLen(array);

    /* *** Free each element *** */
    for (i = 0; i < len; i++)
    {
        it = array[i];
        if (it->login != NULL)
            free(it->login);
        if (it->salt != NULL)
            free(it->salt);
        if (it->hash != NULL)
            free(it->hash);
        free(it);           
    }
    free(array);
}
