# The Sample Application

All of the programs in their final state can be found in the [`software/`](https://github.com/leonjza/frida-boot/tree/master/software) folder. If ever you need to quickly refer to a snippet of code for any reason, this would be a good place to look.

The main program we will be using will be referred to as `pew`, with its source code available in the `software/` folder as well as in the snippet below. Copy the source code and save it in a file called `pew.c`

```c
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
```
