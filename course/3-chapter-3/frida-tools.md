# frida tools

When installing the `frida-tools` pip package, you get a number of command line applications. At the time of writing this workshop, those were:

- `frida` - The Frida REPL
- `frida-discover` - Discover function calls made in a process
- `frida-kill` - Kill a process using Frida
- `frida-ls-devices` - Show devices that have a running Frida server (including USB devices)
- `frida-ps` - A Frida powered `ps` tool
- `frida-trace` - Trace function calls in a process

Feel free to explore some of these tools as they can be useful in different scenarios.

## frida-trace

Sometimes you just don't have the time to write the scripts necessary to quickly instrument an application. Tracing function calls (where you can dump arguments or return values) is such a common action, that the `frida-trace` tool is purpose built for this.

When you run `frida-trace` against a target process, specifying some filters such as module or function names, `frida-trace` will dynamically create the hooks necessary and run the `Interceptor.attach()` function using them.

If the calls that you are tracing are C functions, the operating systems man pages will be consulted to try and determine what the arguments for that function would be and auto populate those for you. Remember, by design Frida makes no assumptions on the arguments for a function, but man page parsing is a neat trick for it!

Let's try it out on our `crypt` binary by tracing the `atoi` call. From `frida-trace --help`, we can see a number of flags can be used to filter the modules and functions you are interested in. In our case, we want the `atoi` function, so we can use the `-i ato*` flag which means any function starting with `ato` should be traced.

```bash
~/code$ frida-trace crypt -i "ato*"
Instrumenting functions...
atof: Auto-generated handler at "/root/code/__handlers__/libc_2.30.so/atof.js"
atoll: Auto-generated handler at "/root/code/__handlers__/libc_2.30.so/atoll.js"
atoi: Auto-generated handler at "/root/code/__handlers__/libc_2.30.so/atoi.js"
atol: Auto-generated handler at "/root/code/__handlers__/libc_2.30.so/atol.js"
Started tracing 4 functions. Press Ctrl+C to stop.

```

Going back to the `crypt` program and entering a number should have the `frida-trace` prompt update with the arguments passed to `atoi`.

```text
Started tracing 4 functions. Press Ctrl+C to stop.
           /* TID 0x152e */
  3803 ms  atoi(nptr="1337
")
```

Pretty cool huh, and pretty easy too! Now you would have also noticed that `frida-trace` said that it auto-generated some handlers, placing them in the `__handlers__` folder. This is a feature of `frida-trace` where any functions that match the filter will have the auto-generated handler placed in the _library name_ -> _function name_ file. In the case of `atoi`, the location is `libc_2.30.so/atoi.js`. If a handler is already defined, `frida-trace` will not auto-generate a new one. Instead, the existing one will get loaded. This means you can quickly make edits if needed.

Open the `atoi.js` file now and you should see the `onEnter` handler defined as:

```javascript
onEnter: function (log, args, state) {
log('atoi(' +
    'nptr="' + args[0].readUtf8String() + '"' +
')');
},
```

The arguments were auto populated with information from `man 3 atoi`. 😎
