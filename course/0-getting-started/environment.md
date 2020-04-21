# Environment

This workshop will be run from within a single docker container that you either downloaded, or built yourself from this workshop's repository. All of the tools required have been pre-installed and configured for you to try and make this easy as possible.

The following core tooling should be available:

- GNU Debugger [`gdb`](https://www.gnu.org/software/gdb/) with the awesome GDB Enhanced Features [`gef`](http://gef.rtfd.io/) assitance tooling.
- The [Frida](https://frida.re/) python command line utilities, [`frida-tools`](https://github.com/frida/frida-tools) which also includes [`frida`](https://github.com/frida/frida) itself.

Other helpers include:

- `vim`, I mean, what else.
- `tmux`, we are going to do a few things at once. You can always just spawn more shells from your host into the container.

Some sample code to play with is also provided, but this needs to be mounted into the container. More information about that can be found in a later section [here](0-getting-started/code).
