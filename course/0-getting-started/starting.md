# Starting the environment

The recommended way to start the environment is with the following command:

```bash
docker run --cap-add SYS_PTRACE --rm -it --name frida-boot -p 9999:80 -v $(pwd)/program:/root/code leonjza/frida-boot
```

This will:

- Start the workshop container using the `leonjza/frida-boot` image on Dockerhub
- Give the container the `SYS_PTRACE` ability so that we can attach a debugger to processes inside of the container.
- Name the resultant container `frida-boot`
- Expose port `9999` on your host OS, forwarding it to port `80` inside the container for the documentation
- Mount the `./program` directory on your host to the `/root/code` directory inside the container
- Clean-up the container when you are finished

## Building yourself

If you would prefer to build the container yourself, you can do that with:

- `git clone https://github.com/leonjza/frida-boot`
- Make modifications if you need to.
- Decide on a name and tag for the container. I usually tag locally built images with `:local`.
- Build the image (from the projects root) with `docker build -t frida-boot:local .`

!> **Note** If you built the image yourself, you need to use the tag name you used in the `docker build` command to start the image.

In either case, the documentation server should be available on port `9999` (unless you change that ofc.).
