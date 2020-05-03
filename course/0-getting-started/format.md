# Workshop Format

This workshop is very hands on. To get the most out of it, it is highly encouraged that you perform each of the steps yourself. For question and answer sections, hints and eventually answers are available for each section. Try and hold off revealing the hints for as long as possible.

## Code

Code blocks with useful snippets of code would typically be formatted like this:

```javascript
let printf = Module.getExportByName(null, "printf");

Interceptor.attach(printf, {
    onEnter: function(args) {
        console.log("In printf()!");
    }
});
```

Often you may want to copy the chunk of code provided. A helper to quickly copy the entire block will pop up if you hover over the code block, revealing a _"Copy to clipboard"_ button.

## Commands

Commands, or other strings such as paths would typically take this format in a sentence.

> To compile the program, run the `gcc *.c -o program` command.
