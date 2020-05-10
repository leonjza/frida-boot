# channels

Let's update our tool so that we implement the previous excercises PIN brute forcer in `crypt` in our own python tool.

```python
import frida
import sys

session = frida.attach("crypt")
script = session.create_script("""
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
""")
script.load()

# block so that the program does not quit.
sys.stdin.read()
```

Running our tool on an instance of `crypt` should yield exactly the same results as in the previous chapters.

## a small refactor

Now one of the big things that you should see in this script is that we have both JavaScipt and Python in a single file. That's fine for small scripts, but not so much for larger programs, so, let's refactor our tool to read the JavaScript from a file instead. This way, we have the Python code in a single file, and the JavaScript code in another. For example:

```javascript
// index.js
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
```

```python
# tool.py
import frida
import sys

with open("index.js", "r") as f:
    agent = f.read()

session = frida.attach("crypt")
script = session.create_script(agent)
script.load()

# block so that the program does not quit.
sys.stdin.read()
```

Excellent. We now have a logical seperation between our agent and the injector. Test your tool to make sure it is still able to brute force the password as expected!

## communication channels

So far, our injector and the agent are completely decoupled from each other. That is that both are technically unaware of what the other is doing, and for the most part that is ok. However, it will often happen that you may need to send data between your Python program and the agent. A few options are available to us for this. Let's start by looking at `send()` and `recv()`.

### send()

With `send()`, we can take arbitrary data from the agent, and send it to the Python injector. The most common use for this case is to use `send()` send some feedback output to the injector, but, you can send any JSON serialisable content with it. If you need to send arbitrary blobs of data that cannot be serialised, the second argument to `send()` can be used for that. For example:

```javascript
var message = '42';
var blob = new Uint8Array(100);
send(message, blob);
```

Edit your agent now, adding a `send()` call to signal when the brute force of the PIN starts, and when it ends.

```javascript
// index.js
var testPinPtr = DebugSymbol.getFunctionByName("test_pin");
var testPin = new NativeFunction(testPinPtr, "int", ["pointer"]);

send("Starting brute");

for (var i = 0; i < 9999; i++) {
    // snip
}

send("Finished brute");
```

If you were to run your tool now it should still function expected, except you wont see the messages you are `send()`-ing! That is because we need to write a small handler that tells our injector what to do when a message comes in from `send()`.

A handler can be added on the `script` object we have in our injector, using the `.on()` method. We are going to respond to messages, so the syntax will be `script.on("message", func)` where `func` is the function to call when we get a message. For example:

```python
# tool.py
import frida
import sys

with open("index.js", "r") as f:
    agent = f.read()

def incoming(message, data):
    print(message)

session = frida.attach("crypt")
script = session.create_script(agent)
script.on("message", incoming)
script.load()

# block so that the program does not quit.
sys.stdin.read()
```

In the snippet above, we have defined a new function called `incoming` that takes two arguments. The `message` and the `data`. These are the same two arguments you would have used in the `send()` call in the agent.  Finally, we defined a `script.on("message", incoming)` line, saying that when a message is received, run the `incoming` function.

Update your script now with this handler, and run it again. You should see the messages are handles correctly.

```text
[ ... ]
Trying: 3427
Trying: 3428
Pin is: 3428
{'type': 'send', 'payload': 'Done with brute force'}
```

?> You can extract only the message by printing the `message["payload"]` in your `incoming` function. Beware though, not all messages have this set, so you will need to check for that as well.

### recv()

Similar to how we can send data from the agent to the injector, the inverse is possible. Using the `recv()` function, your agent can expect input from the Python based program. We can send data from our Python tool to the agent by using the `.post()` function, passing in a JSON formatted payload. One thing to keep in mind when using `recv()` is that it is not a blocking operation by default; ie. your script will not wait for the Python program to `post()` a message before continuing. You can change this if you want by assigning the response to `recv()` to a variable and calling `.wait()` on it.

Just like how we need a handler in the Python world to receive messages, the same is nessesary in the JavaScript agent.

Let's update our tool and see what this looks like.

```javascript
// index.js
var testPinPtr = DebugSymbol.getFunctionByName("test_pin");
var testPin = new NativeFunction(testPinPtr, "int", ["pointer"]);

recv(function(message) {
    console.log("Recieved message: " + message);
});

send('Starting brute force');

for (var i = 0; i < 9999; i++) {
    // snip
}

send('Done with brute force');
```

Running our tool again, we should see the data we sent with the `.post()` method appear in the agent.

```text
[ ... ]
Trying: 3427
Trying: 3428
Pin is: 3428
{'type': 'send', 'payload': 'Done with brute force'}
Recieved message: hello from python!
```
