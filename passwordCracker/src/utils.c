#include "../include/utils.h"

void usage(char *program)
{
    fprintf(stderr, "\nusage : %s -f <shadow> [-b <max_len>] \
[-f <dico>]\n", program);
    fprintf(stderr, "-f <shadow>    file passwords (/etc/shadow)\n");
    fprintf(stderr, "-b <max_len>   brute force attack(4 characters by \
default)\n");
    fprintf(stderr, "-d <dico>      dictionary attack\n");
}
