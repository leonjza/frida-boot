#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>

// man 3 sleep
//  unsigned int sleep(unsigned int seconds);
unsigned int sleep(unsigned int seconds) {

    // you've never slept this well in your life!
    printf("[-] sleep goes brrr\n");
    return 0;
}
