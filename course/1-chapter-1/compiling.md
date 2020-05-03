# Compiling the application

Having familirised ourselves with our sample application a little, we can go ahead and compile it in the container.

## Performing the compile

Inside of the docker container in the `/root/code` directory you should have the new `pew.c` file from the previous section. Let's compile the program using `gcc`. We will tell `gcc` we want to compile the `pew.c` source file and output the result to a program called `pew`. Do this by running `gcc pew.c -o pew`:

```bash
~/code$ gcc pew.c -o pew
~/code$
```

Once the compilation is done, you should have a new ELF binary called `pew` in the same folder. You can run it with `./pew` now.

```bash
~/code$ ./pew
[+] Starting up!
[+] Sleeping for 3 seconds
[+] Sleeping for 4 seconds
[+] Sleeping for 2 seconds
^C
```

If you want to exit the program before the interations complete, simply hit <kbd>ctrl</kbd> + <kbd>c</kbd>.
