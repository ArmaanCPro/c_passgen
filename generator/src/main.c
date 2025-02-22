#include <stdio.h>

#include "Generator.h"

int main(int, char*[])
{
    password_policy pp;
    pp_init(&pp);

    char* pwd = pg_generate_advanced(&pp);
    printf("password 1: %s\n", pwd);
    free(pwd);

    pp.password_length = 100;
    pp.excluded_chars = "qwertyuiopasdfghjkzxcvbnm";
    pwd = pg_generate_advanced(&pp);
    printf("password 2: %s\n", pwd);
    free(pwd);
    pwd = NULL;

    return 0;
}