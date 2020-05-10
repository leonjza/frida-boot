# remote procedure call interface

I'll be honest, all of the things about the `load()` timeout and the intricacies with `send()` and `recv()` are not a lot of fun to work with. Especially given the async nature of JavaScript, if you are not careful you can cause yourself a ton of headaches with these. Instead, Frida also exposes an RPC interface which in my honest opinion is the way to go about building custom tools.

Before we go about refactoring our PIN brute forcer, let's get the basics down first.

## rpc 101

The RPC interface has two key components. The first being the `rpc` object in the JavaScript agent, and the second being the `script.exports` property in the Python world.

?> The `script.exports` property is also available in other language bindings.

In the agent you can define an object such as this after your initialisation code.

```javascript
rpc.exports = {
    brute: function() {
        console.log("Brute function");
    }
}
```

This will define the `brute` function in the agent, and expose it as an RPC export that language bindings such as python can access. Next, after calling `load()` in your injector script, it is possible to access the `brute()` function from Python by calling the function by name on the `script.exports` property. For example:

```python
script.exports.brute()
```

This pattern comes with a wide array of benefits. First, you won't be reaching any timeout errors as nothing is executing during script load. Second, we can now make use of the `brute` function from our Python code which gives us much better control over the code where we can define arguments and act on the return value. In fact, we can implement the brute force script multiple ways now.

## using brute as an RPC function

Let's refactor our brute force script one more time. This time round we will be making use of the RPC interface. The first approach would be to just move all of the logic we already have to the new `brute()` function. For example:

```javascript
rpc.exports = {
    brute: function() {
        var testPinPtr = DebugSymbol.getFunctionByName("test_pin");
        var testPin = new NativeFunction(testPinPtr, "int", ["pointer"]);

        for (var i = 0; i < 9999; i++) {
            console.log("Trying: " + i.toString());
            var pin = Memory.allocUtf8String(i.toString());
            var r = testPin(pin);

            if (r == 1) {
                console.log("Pin is: " + i.toString());
                break;
            }
        }
    }
}
```

Our Python injector will also receive a minor modification to get a handle on the `exports` that our agent exposes.

```python
import frida
import time

with open('index.js', 'r') as f:
    agent = f.read()

def incoming(message, data):
    print(message)

session = frida.attach("crypt")
script = session.create_script(agent)
script.on("message", incoming)
script.load()

rpc = script.exports    # get a handle on the exports

rpc.brute()
```

Notice how I have removed the `sys.stdin.read()` call. When we call `brute()`, the program will wait until it returns. Run this program now and see how the same output we have seen this far is returned.

## implementing brute in python

With the RPC pattern we can modify how we actually perform the brute force. Remember, the brute force is based on the return of `testPin` when given a specific argument. Right now we just loop over a range of numbers in the JavaScript agent, but we can move this to the Python world if we wish.

To do this, lets create a new RPC exports called `tryPin`, that accepts one argument. We will pass this argument from the Python program. Next, we will call the real `testPin()` function with that argument, and return the result back to the Python world.

Add a new RPC function called `tryPin` now.

```javascript
rpc.exports = {
    brute: function() {
        // snip
    },
    testPin: function(n) {
        // new logic
    }
}
```

As for the logic for `tryPin`, let's think about this for a moment. The `brute` function currently has all the parts we need to get a handle on the real `testPin` function. We can either copy and paste that into the `tryPin` method, or, we can extract it entirely out of the `rpc.exports` object and make it available globally. Getting a handle is a really quick operation too, so there is no risk in hitting a timeout when the script loads. With the handle available, we can simply call the real `testPin` and return the results.

So, our agent with the new `tryPin` function would now look something like this:

```javascript
var testPinPtr = DebugSymbol.getFunctionByName("test_pin");
var testPin = new NativeFunction(testPinPtr, "int", ["pointer"]);

rpc.exports = {
    brute: function() {
        for (var i = 0; i < 9999; i++) {
            console.log("Trying: " + i.toString());
            var pin = Memory.allocUtf8String(i.toString());
            var r = testPin(pin);

            if (r == 1) {
                console.log("Pin is: " + i.toString());
                break;
            }
        }
    },
    tryPin: function(n) {
        var pin = Memory.allocUtf8String(n.toString());
        return testPin(pin);
    }
}
```

In the Python world we now need to implement the loop that will call `tryPin` on different values. That would look something like this:

```python
import frida
import time

with open('index.js', 'r') as f:
    agent = f.read()

def incoming(message, data):
    print(message)

session = frida.attach("crypt")
script = session.create_script(agent)
script.on("message", incoming)
script.load()

rpc = script.exports

for x in range(0,9999):
    r = rpc.try_pin(x)
    if r != 0:
        print('Pin is: ' + str(x))
        break
```

Give that a run and check that you get the same PIN is the previous pure JavaScript implement. Then, pause for a moment and ponder about what is actually happening here.... :D
