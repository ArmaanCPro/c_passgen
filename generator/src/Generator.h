#include <sodium.h>
#include <stdlib.h>
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

// helper function to see if a character is in the set
bool is_char_in_set(const char* set, char c)
{
    while (set != NULL)
    {
        if (*set == c)
        {
            return true;
        }
        set++;
    }
    return false;
}


// returns a new array that does not contain the chars_to_remove
char* c_remove_chars(const char* str, const char* chars_to_remove) 
{
    int str_len = strlen(str);
    char* new_str = (char*)malloc(str_len + 1);
    int new_str_index = 0;

    for (int i = 0; i < str_len; i++)
    {
        if (!is_char_in_set(chars_to_remove, str[i]))
            new_str[new_str_index++] = str[i];
    }

    new_str[new_str_index] = '\0';
    return new_str;
}

char* pg_generate_advanced(password_policy* pp)
{
    char* available_chars = (char*)malloc(sizeof(s_LowerCaseChars) + sizeof(s_UpperCaseChars) + sizeof(s_NumbersChars) + sizeof(s_SymbolsChars) + 1);
    char* password = (char*)malloc(pp->password_length + 1);

    available_chars[0] = '\0';

    if (pp->require_lc)
        strcat(available_chars, s_LowerCaseChars);
    if (pp->require_uc)
        strcat(available_chars, s_UpperCaseChars);
    if (pp->require_num)
        strcat(available_chars, s_NumbersChars);
    if (pp->require_sym)
        strcat(available_chars, s_SymbolsChars);

    char* filtered_chars = c_remove_chars(available_chars, pp->excluded_chars);
    free(available_chars);

    for (size_t i = 0; i < pp->password_length; i++)
    {
        unsigned char randomIndex;
        randombytes_buf(&randomIndex, sizeof(randomIndex));
        randomIndex %= strlen(filtered_chars);

        password[i] = filtered_chars[randomIndex];
    }

    password[pp->password_length] = '\0';

    free(filtered_chars);
    return password;
}