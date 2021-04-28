# interceptor return values

Much like arguments, we can update return values as well. To demonstrate this we will hook the function used to get the time intervals to sleep for in `pew` called `rand_range`. There is only one problem though, `rand_range` is not an exported function in a shared library. Instead, it is part of `pew` itself.

## debugsymbol api

Symbols in shared libraries are easily enumerated using API's such as `Module.findExportByName()`. However, when functions are not exported the `Module` API may fail to resolve addresses. Instead, an alternative API exists called `DebugSymbol` that can try and resolve addresses using information in the symbol table. Have a look at the documentation [here](https://frida.re/docs/javascript-api/#debugsymbol).

Let's try and resolve `rand_range` using the Frida REPL. First, try running `Module.getExportByName(null, "rand_range");`.

```text
[Local::pew]-> Module.getExportByName(null, "rand_range");
Error: unable to find export 'rand_range'
    at frida/runtime/core.js:231
```

This should result in an error as no loaded shared library has a function with the name `rand_range`. So, we use the `DebugSymbol` API instead to try and resolve it.

```text
[Local::pew]-> DebugSymbol.getFunctionByName("rand_range");
"0x55d855faa185"
```

?> Try using `gdb` to verify that Frida correctly discovered the address of `rand_range`.

## stripped binaries

It may often happen that you have a stripped binary. That means a binary that has all symbols stripped. If that is the case, even the `DebugSymbol` API will not be able to help you. An alternative strategy in this case would be to determine the offset of the function you are interested in using reverse engineering efforts and calculating the targets functions location after leaking a modules base address with Frida.

For example, let's quickly go back to `gdb` and ask for the address of `rand_range`. Note, if your binary is stripped, this won’t be possible. You will only have the assembly to work with!

```text
~/code$ gdb -q ./pew
gef➤  info functions rand_range
All functions matching regular expression "rand_range":

Non-debugging symbols:
0x0000000000001185  rand_range
```

Alright, `rand_range` is at `0x1185`. That means that if we know the base address of where `pew` is loaded at runtime and we add `0x1185` to that, we should be at the `rand_range` function.

To test this, lets write a small Frida script.

```javascript
var b = Process.getModuleByName("pew").base;
var rand_range = b.add(0x1185);

Interceptor.attach(rand_range, {
    onEnter: function(args) {
        console.log("rand_range(" + args[0] + ", " + args[1] +")");
    }
});
```

After updating our `index.js` with the above snippet, we should see that we have attached to `rand_range()`.

```text
[Local::pew]-> rand_range(0x1, 0x5)
[Local::pew]-> rand_range(0x1, 0x5)
rand_range(0x1, 0x5)
rand_range(0x1, 0x5)
rand_range(0x1, 0x5)
```

Given that we do have symbols, lets update the script to rather use the `DebugSymbol` API instead of manually calculating offsets. The final script should look something like this:

```javascript
var rand_range = DebugSymbol.getFunctionByName("rand_range");

Interceptor.attach(rand_range, {
    onEnter: function(args) {
        console.log("rand_range(" + args[0] + ", " + args[1] +")");
    }
});
```

## modifying return values

From source code we know that `rand_range` returned an integer. Using the optional `onLeave` callback we can see what the return value will be before it returned to the caller. This is because at this stage the original function would have completed.

Let's implement an `onLeave` call back that prints the return value of `rand_range`:

```javascript
var rand_range = DebugSymbol.getFunctionByName("rand_range");

Interceptor.attach(rand_range, {
    onLeave: function(retval) {
        console.log(retval);
    }
});
```

Running this script, the output should be similar to this, logging the return value of `rand_range`:

```text
[Local::pew]-> 0x3
0x3
0x1
0x5
```

We can update the value using `retval.replace()` within the `onLeave` call back. For example:

```javascript
var rand_range = DebugSymbol.getFunctionByName("rand_range");

Interceptor.attach(rand_range, {
    onLeave: function(retval) {
        console.log(retval);
        retval.replace(ptr("0x1"));
    }
});
```

Notice how `pew` only waits one second now :)

## data binding in onenter and onleave

Depending on what your hook does, you may want to affect the return value of a function based on arguments you received. However, both the `onEnter` and `onLeave` call backs have different arguments and by extension has access to different parts of a hooked function.

Using the `this` context within the call backs it’s possible to bind data in the `onEnter` call back and make it available in the `onLeave` callback. For example, if we wanted to make the return value of `rand_range` to be the same as the first argument the function gets:

```javascript
var rand_range = DebugSymbol.getFunctionByName("rand_range");

Interceptor.attach(rand_range, {
    onEnter: function(args) {
        this.arg1 = args[0];
    },
    onLeave: function(retval) {
        console.log(retval);
        retval.replace(ptr(this.arg1));
    }
});
```
