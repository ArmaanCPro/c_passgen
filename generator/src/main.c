#include <stdio.h>

#include "Generator.h"

int main(int, char*[])
{
    password_policy pp;
    pp_init(&pp);
    password_gen pg;
    pg_init(&pg, &pp);

    char* pwd = pg_generate_advanced(&pg);

    printf("password 1: %s\n", pwd);

    pp.password_length = 100;
    pwd = pg_generate_advanced(&pg);
    printf("password 2: %s\n", pwd);
    return 0;
}