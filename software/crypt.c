#include <stdio.h>
#include <string.h>
#include <stdlib.h>

const int open = 1111 ^ 2355;

int test_pin(char *p) {
    int p_int = atoi(p);

    if (p_int == open) {
        return 1;
    }

    return 0;
}

int main(int argc, char **argv) {

    int access = 0;
    char pin[10];

    while (acces == 0) {
        printf("Pin: ");
        fgets(pin, sizeof(pin) - 1, stdin);
        if (test_pin(pin) == 1)
            access = 1;
    }

    printf("Pwnd!!\n");

    return 0;
}
