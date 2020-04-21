# Workshop Code

Throughout this workshop we will be writing some code (or modifying snippets I provide) for various reasons. All of the code you write needs to eventually run in the container. Depending on your preference, there are a few options to help you with the development workflow.

## Code inside the container

The container has `vim` installed. So, if you are comfortable with that, simply edit away in there. The only excercise where this approach will probably not work great will be when we get to building more complex Frida agents with `frda-compile`.

## Code outside of the container, but mounted

The recommended approach would be to have a folder outside of the container, mounted in. This way you may use any editing tools you have on your host (such as `vim`, `vscode` etc.) to modify files, but also have them available inside of the container.

To do this, start the docker container with the `-v` flag, specifying the local path to the code to be available at `/root/code` inside of the container. For example:

```bash
docker run --rm -it -p9999:80 -v $(pwd)/program:/root/code
```

?> The `$(pwd)` section will automatically expand to the current working directory as the `-v` flag expects a full path.
