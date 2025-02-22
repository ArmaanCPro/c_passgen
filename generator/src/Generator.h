#include <sodium.h>
#include <stdbool.h>
#include <string.h>

static const char s_LowerCaseChars[] = "abcdefghijklmnopqrstuvwxyz";
static const char s_UpperCaseChars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char s_NumbersChars[] = "0123456789";
static const char s_SymbolsChars[] = "!@#$%^&*()_+=-[]{}|;':\",./<>?";

typedef struct 
{
    uint64_t password_length;
    bool require_lc;
    bool require_uc;
    bool require_num;
    bool require_sym;
    char* excluded_chars;
} password_policy;

void pp_init(password_policy* policy)
{
    policy->password_length = 10;
    policy->require_lc = true;
    policy->require_uc = true;
    policy->require_num = true;
    policy->require_sym = true;
    policy->excluded_chars = "";
}

typedef struct
{
    password_policy* pc;
} password_gen;

void pg_init(password_gen* pg, password_policy* pc_in)
{
    pg->pc = pc_in;
}


// returns a new array that does not contain the chars_to_remove
char* c_remove_chars(const char* str, const char* chars_to_remove) {
    int i, j;
    int str_len = strlen(str);
    int chars_len = strlen(chars_to_remove);
    char* new_str = (char*)malloc(str_len + 1);
    int new_str_index = 0;

    for (i = 0; i < str_len; i++) {
        int should_remove = 0;
        for (j = 0; j < chars_len; j++) {
            if (str[i] == chars_to_remove[j]) {
                should_remove = 1;
                break;
            }
        }
        if (!should_remove) {
            new_str[new_str_index++] = str[i];
        }
    }

    new_str[new_str_index] = '\0';
    return new_str;
}

char* pg_generate_advanced(password_gen* pg)
{
    char* available_chars = (char*)malloc(sizeof(s_LowerCaseChars) + sizeof(s_UpperCaseChars) + sizeof(s_NumbersChars) + sizeof(s_SymbolsChars) + 1);
    char* password = (char*)malloc(pg->pc->password_length + 1);

    available_chars[0] = '\0';

    if (pg->pc->require_lc)
        strcat(available_chars, s_LowerCaseChars);
    if (pg->pc->require_uc)
        strcat(available_chars, s_UpperCaseChars);
    if (pg->pc->require_num)
        strcat(available_chars, s_NumbersChars);
    if (pg->pc->require_sym)
        strcat(available_chars, s_SymbolsChars);
    
    const char* filtered_chars = c_remove_chars(available_chars, pg->pc->excluded_chars);
    free(available_chars);

    for (size_t i = 0; i < pg->pc->password_length; i++)
    {
        unsigned char randomIndex;
        randombytes_buf(&randomIndex, sizeof(randomIndex));
        randomIndex %= strlen(filtered_chars);

        password[i] = filtered_chars[randomIndex];
    }

    password[pg->pc->password_length] = '\0';

    return password;
}