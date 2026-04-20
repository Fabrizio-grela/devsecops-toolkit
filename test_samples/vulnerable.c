#include <stdio.h>
#include <string.h>

int main() {
    char buffer[64];
    printf("Escribí algo: ");
    gets(buffer); // Buffer Overflow Detectable (Función prohibida)
    
    char dest[10];
    strcpy(dest, buffer); // Buffer Overflow Detectable
    return 0;
}