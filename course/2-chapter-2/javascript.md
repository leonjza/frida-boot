# JavaScript api

As mentioned a few times now, Frida injects a JavaScript engine which can be either Chrome's V8 engine, or the smaller Duktape engine. Both engines have their pro's and con's and whichever you choose will most probably depend on the resources you have available to you. Resources aside, the only real difference to keep in mind is that Duktape does not support modern ES6 syntax, whereas V8 does. This is not too important for now, but keep it in mind when we get to the later parts of this workshop.

## documentation

JavaScript engines aside, the next most important thing you need to know about is the JavaScript API documentation that lives [here](https://frida.re/docs/javascript-api/). Bookmark it!

?> The documentation link refers to the TypeScript bindings, but ignore those for now. We have a section specifically on that later.

From the documentation one can quickly see the wide range of features Frida has. Each of these features are broken up into modules that when combined, can make from incredibly powerful instrumentation. Examples of interesting modules include `Process`, `Module`, `Memory` and `NativeFunction` and all start with an upper case. There are some `global` functions as well such as `hexdump`, `ptr`, `send` and `recv`.

## repl

The Frida REPL can autocomplete most of the Frida modules as well. This makes prototyping very fast from inside the Frida REPL. For example, with the `frida` tool attached to the already running `pew` program, we can start playing with the API right away.

?> Try and hit `TAB` as often as you can, there are plenty of places where it works!

```text
[Local::pew]-> Process.id;
31
```

```text
[Local::pew]-> Process.getModuleByName("libc-2.30.so");
{
    "base": "0x7fe5d9644000",
    "name": "libc-2.30.so",
    "path": "/lib/x86_64-linux-gnu/libc-2.30.so",
    "size": 1830912
}
[Local::pew]->
```

All of this is happening while the target process, `pew` is still running...
