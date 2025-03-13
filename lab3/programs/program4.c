#include<stdio.h>
#include<stdlib.h>
#include<string.h>

char* getString() {
    char* ret = "Hello World!";
    return ret;
}

void program4() {
    printf("String: %s\n", getString());
}

int main() {
    program4();
}