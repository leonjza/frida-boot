# other operating modes

So far we have used Frida in a way that it gets injected externally using the Python bindings. This was mostly because the both the process we wanted to instrument and the Frida tools were on the same computer. This is not always the case like when using Frida on a process running on a mobile phone. In that case you will need to explore other solutions.

Let's take a quick look at the other operating modes; frida-server and frida-gadget.

## frida-server

The `frida-server` binary that you can download from the GitHub [releases](https://github.com/frida/frida/releases) page is a standalone program. When run, it will create a TCP socket listening on localhost on port 27042 where client tools can connect to. You can change this with the `-l` flag to make it listen on a different interface and port combination. For example `./frida-server -l 0.0.0.0:1337`.

The docker container you have using for this workshop has the `frida-server` command available for you to experiment with.

```text
~$ frida-server -h
Usage:
  frida [OPTION…]

Help Options:
  -h, --help                    Show help options

Application Options:
  --version                     Output version information and exit
  -l, --listen=ADDRESS          Listen on ADDRESS
  -d, --directory=DIRECTORY     Store binaries in DIRECTORY
  -D, --daemonize               Detach and become a daemon
  -v, --verbose                 Be verbose
```

If you want to see it in action, rerun the docker container adding a new port mapping with `-p 27042:27042`. Once the container is up, start the server with `frida-server -l 0.0.0.0`. Next, with `frida-tools` installed locally via `pip` (`pip install frida-tools`), try and connect to the server running in the container with `frida-ps -R`.

```bash
# inside the container
~$ frida-server -l 0.0.0.0

```

```bash
# on your host where the container is running
~ » frida-ps -R
PID  Name
--  ---------------------------
 1  bash
11  bash
28  frida-server
 7  nginx: master process nginx
 8  nginx: worker process
 9  nginx: worker process
10  nginx: worker process
12  nginx: worker process
13  nginx: worker process
14  nginx: worker process
15  nginx: worker process
16  nginx: worker process
```

You should see all of the processes running in your container, from your host! Once you know the name of the remote process, you can now connect the `frida` client, attaching to a specific process either by name or by PID.

?> Note, you may try to connect to an `nginx` process in the container, but there are a few problems where. First, there are multiple processes with the same name. Secondly, the `nginx` worker processes are not just called `nginx`, but instead `nginx: worker process`. As a result, you will need to specify the process ID of the target process with the `-p` flag.

```text
~ » frida -R -p 15
     ____
    / _  |   Frida 12.8.19 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/

[Remote::PID::15]->
[Remote::PID::15]-> Process.enumerateModulesSync();
[
    {
        "base": "0x55a889119000",
        "name": "nginx",
        "path": "/usr/sbin/nginx",
        "size": 1118208
    },

[ ... ]
```

Let your imagination go wild! Naturally, the language binding support the same remote targets as the `frida` REPL does (given that its build on top of the same Python bindings).

## frida-gadget

The other form Frida comes in is called the Gadget. Fundamentally it behaves just like the Frida server does with the key difference being that is is a shared library with a constructor that boots it up. When the library is initialised, it also opens a TCP port on local host (more on the configuration later) where one can connect the Frida command line tools.

The Gadget is particularly powerful in the sense that it could be patched into say a mobile application to be loaded early during the applications' startup, allowing for the Frida command line tools to be connected to it and the process it is attached to, instrumented.

In the case of a Linux binary, we can "boot" the gadget using an `LD_PRELOAD` environment variable, or by patching the gadget into the binary as a required shared library. Let's try both.

## frida gadget LD_PRELOAD

We have already spend an extensive amount of time on `LD_PRELOAD` tricks in Chapter 1. We know that we just have to specify the full path to the shared library we want to load as we invoke our program, so let's do that.

The `frida-gadget.so` is located in the `/root` directory in the Docker container.

```text
~/code$ LD_PRELOAD=./../frida-gadget.so ./crypt
[Frida INFO] Listening on 127.0.0.1 TCP port 27042

```

Notice how we don't see the `Pin:` prompt we have come to expect from the `crypt` program, but instead we are shown a new line that Frida is now listening on localhost port 27042. At this stage the program is actually _paused_, waiting for a Frida client to tell it to resume.

This pausing behaviour is the default when it comes to the Gadget, but can be changed (more on that later.).

Alright, lets open another shell in the Docker container and get to a point where we can resume the app. Remember that we are now working on a remote gadget (as in over a TCP socket), so for the Frida command line tools we will be providing the `-R` flag. Try and connect the Frida REPL to the `crypt` program that is already running now.

```text
~$ frida -R crypt
     ____
    / _  |   Frida 12.8.20 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/
Failed to spawn: unable to find process with name 'crypt'
```

The error we get states that it could not find a process called `crypt`. That is because when launched in Gadget mode, the process name from a Frida perspective is also different. Let's check what that is.

```text
~$ frida-ps -R
PID  Name
---  ------
114  Gadget
```

The process is called `Gadget`! Aha, so try and connect the REPL again, but instead of sayin you want to connect to `crypt`, use `Gadget` instead.

```text
~$ frida -R Gadget
     ____
    / _  |   Frida 12.8.20 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/

[Remote::Gadget]->
[Remote::Gadget]-> Process.enumerateModulesSync();
[
    {
        "base": "0x55561e900000",
        "name": "crypt",
        "path": "/root/code/crypt",
        "size": 20480
    },

[ ... ]
```

Notice how when you connected the Frida REPL, the real process also resumed and the `Pin:` prompt is now displayed.

```text
~/code$ LD_PRELOAD=./../frida-gadget.so ./crypt
[Frida INFO] Listening on 127.0.0.1 TCP port 27042
Pin:
```

## frida-gadget patching

Depending on your target environment, using `LD_PRELOAD` may not always be an option. An alternative is to "patch" the target binary, telling it to load the shared library as part of the binaries initialisation routine. The process of patching will heavily depend on your target Operating System. For Linux, we can use a tool called `patchelf` to achieve this.

Before we patch, lets take a look at the libraries `crypt` depends on.

```text
~/code$ ldd crypt
        linux-vdso.so.1 (0x00007ffd5633b000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f39a9977000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f39a9b45000)
```

Now, with `patchelf` we can use the `--add-needed` flag to add the `frida-gadget.so` as a needed library with `patchelf --add-needed ../frida-gadget.so crypt`. After the modification, check out the libraries `crypt` depends on:

```text
~/code$ patchelf --add-needed ../frida-gadget.so crypt
~/code$ ldd crypt
        linux-vdso.so.1 (0x00007ffcdd57b000)
        ../frida-gadget.so (0x00007fc52ef03000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fc52ed3c000)
        libresolv.so.2 => /lib/x86_64-linux-gnu/libresolv.so.2 (0x00007fc52ed24000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fc52ed1f000)
        librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007fc52ed14000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fc52ebcd000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fc52ebac000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fc530751000)
```

Now when you run crypt, you should seed Frida boot up as well!

```text
~/code$ ./crypt
[Frida INFO] Listening on 127.0.0.1 TCP port 27042

```

?> In case you were curious, this `patchelf` method is the basic premise of how the "patching" phase works in [objection](https://github.com/sensepost/objection).

## frida-gadget configuration

The Gadget can be configured to behave in different ways. For example, you can make the Gadget listen on all interface, not just localhost, open a port other than 27042 or, make it load a script and run it by default, all without a Frida client connected.

From the [docs](https://frida.re/docs/gadget/) we can see the format the configuration file takes. In a nut shell, the file should contain one JSON object with a few key/value pairs. An example configuration which is also the default configuration for the gadget is:

```json
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_load": "wait"
  }
}
```

If we wanted to change the behaviour of the Gadget to not pause the program until a Frida tool resumes it, we can change the `on_load` key to `resume`.

```json
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_load": "resume"
  }
}
```

The configuration file itself needs to live next to the Gadget's `.so` file and have the same name with the extension being `.config` instead of `.so`. Save a file with this contents called `frida-gadget.config` and run the patched `crypt` binary again.

```text
~/code$ ./crypt
Pin: [Frida INFO] Listening on 127.0.0.1 TCP port 27042

Pin:
Pin:
```

You should now see the Gadget booted and the application is ready to accept input without first connecting the Frida REPL.

Check out the documentation or more interesting configuration options!
