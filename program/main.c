#include <stdio.h>
#include "tools.h"

int main(int argc, char **argv) {

    if (argc < 2) {
        write_info_string("Please provide an iteration count");
        return 1;
    }

    int iterations = string_to_int(argv[1]);

    char line[50];
    sprintf(line, "Running %d iterations", iterations);
    write_info_string(line);

    write_info_string("Lets go!");

    while(iterations != 0) {
        wait_for_something_nice(1);
        iterations--;
    }

    write_info_string("Done!");

    return 0;
}
