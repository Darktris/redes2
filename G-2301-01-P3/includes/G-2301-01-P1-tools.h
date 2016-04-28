#ifndef _TOOLS_H
#define _TOOLS_H

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"

#define strcmp _strcmp
int _strcmp(const char* a, const char* b);
#define strlen _strlen
size_t _strlen(const char* s);
#define free _free
void _free(void* a);
#endif 
