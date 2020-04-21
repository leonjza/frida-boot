# Why hooking / instrumentation

Hooking function calls in a program provides us with an incredibly powerful ability to see whats happening "under the hood" of a running program or, to modify internal logic. To help understand this, let's look at an example.

Imagine some C functions for a moment that is responsible for some crypto related work or calculating a key. Ignoring the actual crypto implementation for a moment, imagine the function prototypes were `void encrypt(int *data, char *key)`, taking in a buffer to encrypt and maybe a key and `char * getKey()` that just return's a key.

The ability to hook into the `encrypt()` function would mean it would be possible to see what the value of `*key` would be, at runtime. Hooking `getKey()` would mean we could both see the value that is returned, or, set our own value to be returned to the program.
