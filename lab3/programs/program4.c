#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* getString() {
    char* ret = malloc(100);  
    if (ret == NULL) {
        printf("Memory allocation failed\n");
        exit(1);
    }
    strncpy(ret, "Hello World!", 99);  
    ret[99] = '\0';
    return ret;
}

void program4() {
    char* str = getString();
    printf("String: %s\n", str);
    free(str);
}

int main() {
    program4();
}
