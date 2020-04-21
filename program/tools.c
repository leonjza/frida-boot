#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#ifdef __linux__
    #include <unistd.h>
#elif _WIN32
    #include <Windows.h>
#endif

int random_int(int min, int max) {
    srand(time(NULL));
    return min + rand() % (max+1 - min);
}

int string_to_int(char *s) {
    return atoi(s);
}

void write_info_string(const char *s) {
    time_t t = time(NULL);
    char *t_str = ctime(&t);
    t_str[strlen(t_str) - 1] = '\0';

    printf("(%s) (tool) %s\n", t_str, s);
}

void wait_for_something_nice(int t) {

    // randomise t
    t = t * random_int(1, 5);

    char line[20];
    sprintf(line, "Waiting for: %d", t);
    write_info_string(line);

#ifdef __linux__
    sleep(t);
#elif _WIN32
    Sleep(t * 1000);
#endif
}

