# Workshop Code

In this workshop you are going to be a polyglot programmer. That means, you will be writing code (or modifying snippets) in a wide variety in programming languages (sometimes more than one language in a file). Embrace it, it really is a lot of fun! All of the code you write needs to eventually run in the container. Depending on your preference, there are a few options to help you with the development workflow.

## Code inside the container

The container has `vim` installed. So, if you are comfortable with that, simply edit away in there. The only exercise where this approach will probably not work great will be when we get to building more complex Frida agents with `frida-compile`.

## Code outside of the container, but mounted

The recommended approach would be to have a folder outside of the container, mounted in. This way you may use any editing tools you have on your host (such as `vim`, `vscode` etc.) to modify files, but also have them available inside of the container.

To do this, start the docker container with the `-v` flag, specifying the local path to the code to be available at `/root/code` inside of the container. For example:

```bash
docker run --rm -it -p9999:80 -v $(pwd)/code:/root/code
```

?> The `$(pwd)` section will automatically expand to the current working directory as the `-v` flag expects a full path.
