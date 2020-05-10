# building python tools

Up until now we have written some simple Frida scripts. There is nothing wrong with the approach we have taken so far, however, in the longer term as your project or tool grows, it may be hard to maintain it this way.

There are a number of approaches to go about more longer term tool development. Let's take a look at some of those. We will be focussing on using the Frida [Python bindings](https://github.com/frida/frida-python)to inject instrumentation into a target process, however you can also have a look at the NodeJS, Swift, C or even .NET bindings if you prefer those.

!> Don't confuse Frida bindings with language interoperability. For example, the .NET bindings simply allow you to interact with Frida programattically to inject into and instrument a target process from a .NET program. Having .NET language interop is a completely different topic.

Let's explore some options do built python based tools.

## simple python tool

Wrapping your instrumentation logic into a simple python script is most probably the second most popular method to write Frida based tools (vs. just providing the JavaScript and loading with `frida -l script.js`). Before we write the instrumentation JavaScript, let's setup a small skeleton to use.

?> There are some great examples [here](https://github.com/frida/frida-python/tree/master/examples)

```python
import frida
import sys

session = frida.attach("pew")
script = session.create_script("""
// JavaScript
""")
script.load()

# block so that the program does not quit.
sys.stdin.read()
```

This skeleton will attach to the local process called `pew`, inject a script (that has no logic at the moment) and load it causing it to be run in the target process. Finally, a small hack is done to block the program so that it does not exit. Without this our tool would simply exit. No idea if we have some heavy lifting to do still!

Add some logic to your script now. Maybe something simple to log the version of Frida in use.

```javascript
console.log("Frida version is: " + Frida.version);
```

Run your tool after starting the `pew` program and you should see something like this:

```text
~/code$ python3 tool.py
Frida version is: 12.8.20
^C
KeyboardInterrupt
~/code$
```

?> It is also possible to `spawn()` using the Frida Python bindings.

Neat! Now you can add any logic you want really, and it obviously depends a bit on your tool what you do.
