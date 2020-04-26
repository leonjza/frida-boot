# Internals

So far we have seen how we can use `LD_PRELOAD` to hook the function call to `sleep()`. But what happens under the hood when we do this? To try and get a better view of the internals of this in preperation for playing with Frida, lets attach a debugger and step through the process of resolving a function.

## gdb quick start

The debugger we are going to use is the GNU Debugger, `gdb`. It's super popular and not too hard to use. Here are some basic commands we are going to use:

- `r` to "run" our program.
- `b` to set a "breakpoint".
- `s` to "step" a function.
- `si` to "step instruction".
- `info functions` to "list functions" in the binary.
- `info break` to list our breakpoints.
- `del <index>` to delete a breakpoint with the index obtained with `info break`.

To start the debugging session on our test binary called `sleep_test`, simply run `gdb -q ./sleep_test`. You should pre persented with a prompt, similar to this:

?> `-q` just silences some default banners.

![gdb-start](../_media/gdb-start.png)

Look at you! Already debugging! 🎉 To quit, just type `q` and hit enter.

## Enumerate the app

While we have the source code for this application (given that we wrote it), this will very rarely be the case. So, imagine for a moment you did not write the application you are debugging (or have the source code) and need to figure out what's inside the app.

### Using nm

Before we use the debugger again, lets see how we can get an idea of which _symbols_ exists in the binary using the `nm` tool. Type `nm -D sleep_test` and check the output:

```bash
$ nm -D sleep_test
                 w __cxa_finalize
                 w __gmon_start__
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
                 U __libc_start_main
                 U printf
                 U sleep
```

Here we asked `nm` to dump the _Dynamic Symbol Table_ of the binary, which in our case translates to all of the functions that will be looked up at runtime. Try `nm` on some other programs like `bash`. `nm` expects a full path, so you can use something like `nm -D $(which bash)`.

```bash
$ nm -D $(which bash)
                 U abort
000000000003e500 T absolute_pathname
000000000003e560 T absolute_program
                 U access
0000000000079040 T add_alias
00000000000d4850 T add_history
00000000000d4790 T add_history_time

[... snip ...]
```

You will notice bash has many, many more symbols with a wide variety of flags a well! Lots of hooking opprtunities :)

?> To learn more about what the flags like `U`/`T`/`w` etc. mean, check out `man nm`.

Symbols with the `U` flag mean "The symbol is undefined." (from `man nm`). This means that the dynamic linker will at runtime try and find the location for the function in any linked libraries (most often in libc) and use that function going forward.

### Using gdb

After opening our program in `gdb`, we could maybe ask for the available functions symbols. We can do this with `info functions`:

```text
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001030  printf@plt
0x0000000000001040  sleep@plt
0x0000000000001050  __cxa_finalize@plt
0x0000000000001060  _start
0x0000000000001090  deregister_tm_clones
0x00000000000010c0  register_tm_clones
0x0000000000001100  __do_global_dtors_aux
0x0000000000001140  frame_dummy
0x0000000000001145  main
0x0000000000001180  __libc_csu_init
0x00000000000011e0  __libc_csu_fini
0x00000000000011e4  _fini
```

Great. We have a few symbols to work with. The first function we will be interested in would be `main()` which is effectively the entrypoint for our program. While its not the first code that gets executed when the program starts, for now just know that this is where the code we wrote starts. Next, we can see `printf@plt` and `sleep@plt`. Let's focus on these two for now.

When we used `nm` in the prevous section, we saw that these symbols were marked as `U` (undefined). Within `gdb` however we get this `@plt` section. The Procedure Linkage Table (PLT) is essentially just a marker to tell the program that when we compiled the program, we did not know where `sleep` or `printf` was, and the dynamic linker should find those at runtime. The PLT is the entrypoint for that function resolution logic which will reference a section called the Global Offset Table (GOT) for addresses. The GOT is updated after the dynamic linker successfully resolved a functions' address the first time. Once resolved, the program will jump to the real `printf` and continue as normal. Next time the program wants to use `printf`, the offset in the GOT will be used.

![plt-got](../_media/plt-got.png)

Let's watch this in action using `gdb`

## debugging sleep_test

Fire up `gdb`, specifying `sleep_test` as the target to debug.

```bash
$ gdb -q ./sleep_test
GEF for linux ready, type `gef' to start, `gef config' to configure
75 commands loaded for GDB 9.1 using Python engine 3.8
[*] 5 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./sleep_test...
(No debugging symbols found in ./sleep_test)
gef➤
```

Next, let's dissassemble the `main` function and see what the machine code for it looks like.

```bash
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001155 <+0>: push   rbp
   0x0000000000001156 <+1>: mov    rbp,rsp
   0x0000000000001159 <+4>: sub    rsp,0x10
   0x000000000000115d <+8>: lea    rdi,[rip+0xea0]        # 0x2004
   0x0000000000001164 <+15>: call   0x1030 <puts@plt>
   0x0000000000001169 <+20>: mov    DWORD PTR [rbp-0x4],0x3
   0x0000000000001170 <+27>: mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001173 <+30>: mov    esi,eax
   0x0000000000001175 <+32>: lea    rdi,[rip+0xe99]        # 0x2015
   0x000000000000117c <+39>: mov    eax,0x0
   0x0000000000001181 <+44>: call   0x1040 <printf@plt>
   0x0000000000001186 <+49>: mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001189 <+52>: mov    edi,eax
   0x000000000000118b <+54>: call   0x1050 <sleep@plt>
   0x0000000000001190 <+59>: jmp    0x1170 <main+27>
End of assembler dump.
```

We don't have to dive into what the assembly actually means line by line. Instead, the lines containing a `call` to a function with the `@plt` suffix is of interest to us now.

```text
   0x0000000000001164 <+15>: call   0x1030 <puts@plt>
   0x0000000000001181 <+44>: call   0x1040 <printf@plt>
   0x000000000000118b <+54>: call   0x1050 <sleep@plt>
```

?> Notice the call to `puts`. This is for the first line where we wrote the string "Starting up!", but because of compiler optimisations, the fuction got replaced to a `puts`.

Let's go ahead and put a breakpoint on the `main` function of our program. We can do this with:

```bash
gef➤  b *main
Breakpoint 1 at 0x1155
```

You can see the list of breakpoints you have with `info br`.

```bash
gef➤  info br
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000001155 <main>
```

If you wanted to, you could delete that breakpoint now with `del 1`.

Alright, next, we run the program with `r`. Hitting `r` and pressing enter should almost immediately hit our breakpoint as `main` is invoked quite early in the programs execution flow. It is a lot of information to digest, especially of this is the first time you are seeing this. Don't worry, we don't need to understand everything now ;)

The first parts of the output you will get when hitting a breakpoint is the CPU register and 'stack' region of memory.

![breakpoint](../_media/breakpoint-1.png)

Scrolling down towards the end of the outout, we should see the _code_ and _trace_ sections. These are the only sections we are really going to be interested in. The _code_ section contains the instructions the CPU is going to perform. The _trace_ section is a dynamic view that tries and show context of the functions that have been called. For many reasons this view can be incorrect given that stack frames may be corrupt.

![code-stack](../_media/code-stack.png)

The view you are looking at now can be retreived at anytime while a program is running by issuing the `context` command.

### libc function resolution

With our program paused at the start of the `main` function, let's step through the machine code and observe how libc functions gets resolved. We are not going to step through the entire process, but rather just watch how it does get resolved once, and not again.

To step to the next instruction in the `main` function, enter `si` (step instruction) in the debugger, and watch as the context is updated with instruction pointer moving from `push rbp` to `mov rbp, rsp`.

For example:

```bash
# code section
   0x5563c300f147 <__do_global_dtors_aux+55> add    bl, al
   0x5563c300f149 <__do_global_dtors_aux+57> nop    DWORD PTR [rax+0x0]
   0x5563c300f150 <frame_dummy+0>  jmp    0x5563c300f0d0 <register_tm_clones>
 → 0x5563c300f155 <main+0>         push   rbp
   0x5563c300f156 <main+1>         mov    rbp, rsp
   0x5563c300f159 <main+4>         sub    rsp, 0x10
   0x5563c300f15d <main+8>         lea    rdi, [rip+0xea0]        # 0x5563c3010004
   0x5563c300f164 <main+15>        call   0x5563c300f030 <puts@plt>
   0x5563c300f169 <main+20>        mov    DWORD PTR [rbp-0x4], 0x3
```

Type `si` and hit `enter`:

```bash
# code section
   0x5563c300f149 <__do_global_dtors_aux+57> nop    DWORD PTR [rax+0x0]
   0x5563c300f150 <frame_dummy+0>  jmp    0x5563c300f0d0 <register_tm_clones>
   0x5563c300f155 <main+0>         push   rbp   # RIP was here
 → 0x5563c300f156 <main+1>         mov    rbp, rsp
   0x5563c300f159 <main+4>         sub    rsp, 0x10
   0x5563c300f15d <main+8>         lea    rdi, [rip+0xea0]        # 0x5563c3010004
   0x5563c300f164 <main+15>        call   0x5563c300f030 <puts@plt>
   0x5563c300f169 <main+20>        mov    DWORD PTR [rbp-0x4], 0x3
   0x5563c300f170 <main+27>        mov    eax, DWORD PTR [rbp-0x4]
```

Neat, you have stepped one instruction in the debugger. Many of the context views updated doing this, but again we are only really interested in the _code_ and _trace_ sections. Since we have not called any functions outside of `main`, the trace will currently just show that we are still in the `main()` function.

?> After entering `si` and hitting `enter`, the next time you hit `enter`, the last command (`si` in this case) will be run again.

Continue stepping until you enter the `puts@plt` function. This will be the case after a few `si` invocations and will evnetually look like this:

![puts](../_media/enter-puts.png)

At this point you should see that the _trace_ section now has two entries; `#0 puts@plt()` -> `#1 main()`. This means we are in the `puts@plt` function, called from the `main()` function.

We are not really interested in `puts` right now (even though the same thing as what is going to happen to `printf` is about to happen here), lets continue out of this function. Do so with a sinlge run of the `s` (step) command.

![puts](../_media/real-puts.png)

Notice how the trace changed the current from `puts@plt` to `puts`. You are now in the _real_ `puts` function after the Dynamic Linker resolved it. One more time, step out of it with `s` so that we end up in main again right after the call to `puts@plt`.

```bash
   0x561c59e19159 <main+4>         sub    rsp, 0x10
   0x561c59e1915d <main+8>         lea    rdi, [rip+0xea0]        # 0x561c59e1a004
   0x561c59e19164 <main+15>        call   0x561c59e19030 <puts@plt>
 → 0x561c59e19169 <main+20>        mov    DWORD PTR [rbp-0x4], 0x3
   0x561c59e19170 <main+27>        mov    eax, DWORD PTR [rbp-0x4]
   0x561c59e19173 <main+30>        mov    esi, eax
   0x561c59e19175 <main+32>        lea    rdi, [rip+0xe99]        # 0x561c59e1a015
   0x561c59e1917c <main+39>        mov    eax, 0x0
   0x561c59e19181 <main+44>        call   0x561c59e19040 <printf@plt>
```

#### the global offset table

At this stage it probably makes sense to have a look at the Global Offset Table (GOT) we have so far. The GOT should contain all of the resolved function addresses that have been through the dynamic linker. The `gdb` setup you have makes use of `gef` that has a pretty neat GOT status tool. Invoke it by running `got`.

![got](../_media/got.png)

The output shows us that `puts` has been resolved (in the green colour) and `printf` and `sleep` has not yet been resolved (yellow colour). While the colours are a nice indicator, the memory addresses for these functions also serve as a hint on the status. Running the `vmmmap` command should show you the memory ranges applicable to this program, and by checking the current address for the functions you can also deduce if they have been resolved yet.

```bash
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000561c59e18000 0x0000561c59e19000 0x0000000000000000 r-- /root/sleep_test
0x0000561c59e19000 0x0000561c59e1a000 0x0000000000001000 r-x /root/sleep_test
[ ... ]
0x00007f27ece91000 0x00007f27eceb6000 0x0000000000000000 r-- /lib/x86_64-linux-gnu/libc-2.30.so
[ ... ]
```

### following printf

Let's continue stepping though `main` with `si`. If you are unsure where exactly you are now, enter the `context` command to see. Step until you reach the `call printf@plt` instruction.

![printf-args](../_media/printf-args.png)

?> Notice the new "arguments (guessed)" section. This is something `gef` does for you to try and help debugging. It's pretty spot on in this case given that we gave `printf` a format string and the value `3`.

The very first instruction after the `call` is a jump to the GOT region with `jmp    QWORD PTR [rip+0x2fda]`. The next is to push `0x1` to the stack and then jump to another address. Stepping through this code you will notice the first jump to the GOT section is not taken. Instead, the `0x1` is pushed to the stack and the following jump _is_ taken.

This process is really the beginning of the Dynamic linker doing its thing. You can step quite a few instructions to get a feel for how complex this process really is. :D Just keep going with `si`. Even though `gef` shows a nice trace in the context output, you can ask `gdb` to generate you a backtrace as well. Do this with `bt`.

```text
gef➤  bt
#0  0x00007f2423fd1310 in ?? () from /lib64/ld-linux-x86-64.so.2
#1  0x00007f2423fd5af3 in ?? () from /lib64/ld-linux-x86-64.so.2
#2  0x00007f2423fdc44a in ?? () from /lib64/ld-linux-x86-64.so.2
#3  0x00005610dfd2c186 in main ()
gef➤
```

After running `si` a few times, you are probably going to be pretty deep into the dynamic linker doing its thing. We don't have to understand all of that, just that its a complex process. Let's return all the way back to `main` again. We can do this by entering the `finish` command which should break on return of the current function. Depending on how far you stepped, you may need to `finish` a few times before you will be back to `main` right after the call to `printf@plt`.

```text
# Code
   0x55568ad8c175 <main+32>        lea    rdi, [rip+0xe99]        # 0x55568ad8d015
   0x55568ad8c17c <main+39>        mov    eax, 0x0
   0x55568ad8c181 <main+44>        call   0x55568ad8c040 <printf@plt>
 → 0x55568ad8c186 <main+49>        mov    eax, DWORD PTR [rbp-0x4]
   0x55568ad8c189 <main+52>        mov    edi, eax
   0x55568ad8c18b <main+54>        call   0x55568ad8c050 <sleep@plt>
   0x55568ad8c190 <main+59>        jmp    0x55568ad8c170 <main+27>
   0x55568ad8c192                  nop    WORD PTR cs:[rax+rax*1+0x0]
   0x55568ad8c19c                  nop    DWORD PTR [rax+0x0]
# Trace
[#0] 0x55568ad8c186 → main()
```

Given that our program is in the infinite loop at this stage with the call to jump back in the program (with `jmp    0x55568ad8c170 <main+27>`), lets step all the way to where `printf@plt` gets called again. Enter the `call` and step the instruction `jmp    QWORD PTR [rip+0x2fda]`. You should notice that this time we are immediately in the real `printf`. Pretty cool eh? The `got` command show now show that all of the libc calls we make are fully resolved.

## debugging sleep_test with LD_PRELOAD

So far we have seen how the dynamic linker resolved libc functions (sort-of), storing the results in the GOT so that the next time the same function is called it knows where it is. How does that process look when we are using `LD_PRELOAD`?

Not much different to be honest. Let's take a look. We are going to start up a new debuggig session for `sleep_test` and like before, set a breakpoint on `main` too. However, before we run the program (with `r`), we are going to set the `LD_PRELOAD` environment vaiable within `gdb` first. Do this with `set environment LD_PRELOAD ./fake_sleep.so`. For example:

```text
gef➤  b *main
Breakpoint 1 at 0x1155
gef➤  set environment LD_PRELOAD ./fake_sleep.so
gef➤  r
```

After running the program and hitting the first breakpoint, you can inspect the current processes' environment variables with `show env`.

```bash
gef➤  show env
HOSTNAME=565eac426e0d

[ ... snip ... ]

LINES=39
COLUMNS=138
LD_PRELOAD=./fake_sleep.so
gef➤
```

Checking the processes virtual memory mapping should also show our extra shared library was loaded and is ready to use:

```bash
gef➤  vmmap fake_sleep
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00007fe9fa615000 0x00007fe9fa616000 0x0000000000000000 r-- /root/fake_sleep.so
0x00007fe9fa616000 0x00007fe9fa617000 0x0000000000001000 r-x /root/fake_sleep.so
0x00007fe9fa617000 0x00007fe9fa618000 0x0000000000002000 r-- /root/fake_sleep.so
0x00007fe9fa618000 0x00007fe9fa619000 0x0000000000002000 r-- /root/fake_sleep.so
0x00007fe9fa619000 0x00007fe9fa61a000 0x0000000000003000 rw- /root/fake_sleep.so
```

We don't have to go through all of the detail again to see how the first time something like `printf` is called first invokes the dynamic linker. Instead, lets place a breakpoint at the end of the _while_ loop we have in the program, and inspect the GOT from there. With `gdb` paused at the breakpoint we set at `main`, lets disassemble the function again to see the mapped memory addresses for the instructions in the function.

```bash
gef➤  disas main
Dump of assembler code for function main:
=> 0x0000558523b25155 <+0>: push   rbp
   0x0000558523b25156 <+1>: mov    rbp,rsp
   0x0000558523b25159 <+4>: sub    rsp,0x10
   0x0000558523b2515d <+8>: lea    rdi,[rip+0xea0]        # 0x558523b26004
   0x0000558523b25164 <+15>: call   0x558523b25030 <puts@plt>
   0x0000558523b25169 <+20>: mov    DWORD PTR [rbp-0x4],0x3
   0x0000558523b25170 <+27>: mov    eax,DWORD PTR [rbp-0x4]
   0x0000558523b25173 <+30>: mov    esi,eax
   0x0000558523b25175 <+32>: lea    rdi,[rip+0xe99]        # 0x558523b26015
   0x0000558523b2517c <+39>: mov    eax,0x0
   0x0000558523b25181 <+44>: call   0x558523b25040 <printf@plt>
   0x0000558523b25186 <+49>: mov    eax,DWORD PTR [rbp-0x4]
   0x0000558523b25189 <+52>: mov    edi,eax
   0x0000558523b2518b <+54>: call   0x558523b25050 <sleep@plt>
   0x0000558523b25190 <+59>: jmp    0x558523b25170 <main+27>
End of assembler dump.
```

The instruction at the end of our while loop is the `jmp` call back to a position in `main`, which in my case was at `0x0000558523b25190`. So, set a breakpoint on that address with `b *0x0000558523b25190`.

!> Your address will probably be different, so update it with the correct location in the `b` command.

Next, we continue the program's execution with the `c` command.

```text
gef➤  c
Continuing.
[+] Starting up!
[+] Sleeping for 3 seconds
[-] sleep goes brrr

Breakpoint 2, 0x0000558523b25190 in main ()
[ ... ]
```

At this point, we should be at the `jmp` instruction. Entries in the GOT should also have all been resolved. Let's check out the GOT.

```bash
gef➤  got

GOT protection: Partial RelRO | GOT functions: 3

[0x558523b28018] puts@GLIBC_2.2.5  →  0x7f61759dc000
[0x558523b28020] printf@GLIBC_2.2.5  →  0x7f61759bc440
[0x558523b28028] sleep@GLIBC_2.2.5  →  0x7f6175b2e115
```

In `gdb`, we can ask for information about a memory address. We can do this with the `info symbol` command, which takes one argument. Lets check out the three addresses we have in the GOT, to see where they are from.

```bash
gef➤  info symbol 0x7f61759dc000
puts in section .text of /lib/x86_64-linux-gnu/libc.so.6

gef➤  info symbol 0x7f61759bc440
printf in section .text of /lib/x86_64-linux-gnu/libc.so.6

gef➤  info symbol 0x7f6175b2e115
sleep in section .text of ./fake_sleep.so
```

As you can see, all of the function's except for `sleep` correctly resolved to their `libc` locations. As mentioned in the [`LD_PRELOAD`](1-chapter-1/ld_preload) section, libraries in the `LD_PRELOAD` environment variable get preference when the dynamic linker resolves functions. We just saw that happen!

### using the real sleep

One last thing. Remember the code we wrote to call `dlsym` to get the real address of `sleep` (hopefully in libc)? Let's see what that looks like as well. You know, while we have been getting super comfortable with a debugger :)

From the output of the `got` command, we could see that `sleep` resolved to an address that lives in our `fake_sleep.so` shared library. We can ask `gdb` to disassemble that function so that we can see what it's machine code looks like. For example:

```bash
gef➤  got

GOT protection: Partial RelRO | GOT functions: 3

[0x558523b28018] puts@GLIBC_2.2.5  →  0x7f61759dc000
[0x558523b28020] printf@GLIBC_2.2.5  →  0x7f61759bc440
[0x558523b28028] sleep@GLIBC_2.2.5  →  0x7f6175b2e115

# we got sleep @ 0x7f6175b2e115
gef➤  disas 0x7f6175b2e115
Dump of assembler code for function sleep:
   0x00007f6175b2e115 <+0>: push   rbp
   0x00007f6175b2e116 <+1>: mov    rbp,rsp
   0x00007f6175b2e119 <+4>: sub    rsp,0x20
   0x00007f6175b2e11d <+8>: mov    DWORD PTR [rbp-0x14],edi
   0x00007f6175b2e120 <+11>: lea    rdi,[rip+0xed9]        # 0x7f6175b2f000
   0x00007f6175b2e127 <+18>: call   0x7f6175b2e030 <puts@plt>
   0x00007f6175b2e12c <+23>: mov    DWORD PTR [rbp-0x14],0x1
   0x00007f6175b2e133 <+30>: lea    rsi,[rip+0xeda]        # 0x7f6175b2f014
   0x00007f6175b2e13a <+37>: mov    rdi,0xffffffffffffffff
   0x00007f6175b2e141 <+44>: call   0x7f6175b2e040 <dlsym@plt>
   0x00007f6175b2e146 <+49>: mov    QWORD PTR [rbp-0x8],rax
   0x00007f6175b2e14a <+53>: mov    eax,DWORD PTR [rbp-0x14]
   0x00007f6175b2e14d <+56>: mov    rdx,QWORD PTR [rbp-0x8]
   0x00007f6175b2e151 <+60>: mov    edi,eax
   0x00007f6175b2e153 <+62>: call   rdx
   0x00007f6175b2e155 <+64>: leave
   0x00007f6175b2e156 <+65>: ret
End of assembler dump.
gef➤
```

?> You can also just run `disas sleep` here, `gdb` will resolve the function in the background for you.

Again, we don't have to know an awful lot about what all of this assembly means. The parts we are interested in are usually the `call` commands, and here we can see there is an instruction that says `call rdx`. So, whatever value is in the `RDX` register, this code will make a call to that.

So inspect that happening, lets add another breakpoint on this instruction. I will do it with `b *0x00007f6175b2e153`, but you need to use the address you have for the same instruction. Remember you can check the breakpoints you have with `info br`.

```bash
gef➤  info br
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000558523b25155 <main>
    breakpoint already hit 1 time
2       breakpoint     keep y   0x0000558523b25190 <main+59>
    breakpoint already hit 1 time
3       breakpoint     keep y   0x00007f6175b2e153 <sleep+62>
```

With our breakpoint set, we can continue the execution of the program with `c`. This time round, the program should stop right before the `call rdx` instruction is executed.

```bash
# Code section
   0x7f6175b2e14a <sleep+53>       mov    eax, DWORD PTR [rbp-0x14]
   0x7f6175b2e14d <sleep+56>       mov    rdx, QWORD PTR [rbp-0x8]
   0x7f6175b2e151 <sleep+60>       mov    edi, eax
 → 0x7f6175b2e153 <sleep+62>       call   rdx
   0x7f6175b2e155 <sleep+64>       leave
   0x7f6175b2e156 <sleep+65>       ret
   0x7f6175b2e157                  add    BYTE PTR [rax-0x7d], cl
   0x7f6175b2e15a <_fini+2>        in     al, dx
   0x7f6175b2e15b <_fini+3>        or     BYTE PTR [rax-0x7d], cl
```

We can inspect that value of the `RDX` register from the context view `gef` gives us here, or, we can dump it with `x $rdx`.

```bash
gef➤  x $rdx
0x7f6175a30d60 <sleep>: 0x8b4828ec83485355
```

In my case, `RDX` contained the value `0x7f6175a30d60`. Using the `info symbol` command, we can see where that points to. You can use either the address that you just revealed in `RDX` as an argument, or dynamically refer to it with the `$rdx` variable.

```bash
gef➤  info symbol $rdx
sleep in section .text of /lib/x86_64-linux-gnu/libc.so.6
```

The real address for `sleep` in libc!

## summary

In the last example, what you hopefully took from that was that with our own shared library combined with `LD_PRELOAD`, we made the dynamic linker resolve *our* `sleep` function instead of the one available in libc. Then, inside of our own `sleep`, we used `dlsym` to resolve the real `sleep` function in libc.

![plt-got-ld_preload](../_media/plt-got-ld_preload.png)
