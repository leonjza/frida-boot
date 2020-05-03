# frida hook arguments

So far we have written a simple function hook that allows us to spy on calls to `sleep()`. According to `man 3 sleep`, `sleep()` takes one integer argument signalling for how long the should sleep occur. In the `LD_PRELOAD` example we modified that sleep duration, so lets replicate that with Frida.

We should already have a Frida script from the [previous section](2-chapter-2/sleep#attaching-to-sleep), so let's continue editing that.

## the args variable

Using the `Interceptor`, the `onEnter` callback receives a single argument typically called `args`. This variable is actually an array of the arguments the function received. That means that `arg[0]` would be the first argument, `arg[1]` the second and so forth.

There is one gotcha with the `args` variable though. It has no idea how many arguments the original function received. `args.length()` is not valid. Taking `sleep()` as an example, we should get the argument it received with `arg[0]`. However, if we try and work with say `arg[1]` or `arg[9]`, those are not arguments but other values from the stack.

One more tip, values returned by dereferencing `args` by index are actually `NativePointer`'s meaning you can call any of the methods available on the `NativePointer` Frida API on the argument values themselves.

Update the Frida script to print out the first argument we got for `sleep()`. Notice how as soon as you save the file, the Frida REPL automatically reloaded the script and the instrumentation updated. A little faster than that `LD_PRELOAD` method eh? Syntax errors while you are writing your Frida script is also ok. Frida won't crash the target process and instead just let you know something is wrong.

```javascript
var sleep = Module.getExportByName(null, "sleep");

Interceptor.attach(sleep, {
    onEnter: function(args) {
        console.log("[*] Argument for sleep() => " + parseInt(args[0]));
        console.log("[*] Sleep from Frida!");
    },
    onLeave: function(retval) {
        console.log("[*] Done sleeping from Frida!");
    }
});
```

## overriding arguments

Modifying argument values is just as simple as printing them! All you need to do is assign them. Given that we are working with the first argument, let's update the sleep to only one second. We can do that by saying `args[0] = ptr("0x1")`. That's really it.

```javascript
var sleep = Module.getExportByName(null, "sleep");

Interceptor.attach(sleep, {
    onEnter: function(args) {
        console.log("[*] Argument for sleep() => " + parseInt(args[0]));
        console.log("[*] Overriding argument to 1");
        args[0] = ptr("0x1");   // short for new NativePointer("0x1");
    },
    onLeave: function(retval) {
        console.log("[*] Done sleeping from Frida!");
    }
});
```
