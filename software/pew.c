#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

int rand_range(int min, int max) {
    return min + rand() % (max+1 - min);
}

int main() {

    printf("[+] Starting up!\n");

    int d;
    srand(time(NULL));

    while(1) {
        d = rand_range(1, 5);

        printf("[+] Sleeping for %d seconds\n", d);
        sleep(d);
    }
}
