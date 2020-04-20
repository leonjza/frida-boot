# Frida Boot 👢

Welcome to Frida Boot! A binary instrumentation workshop using [frida](https://frida.re/)!

## Using this documentation

If you are not already doing so, make sure you browse to the port exposed by the docker container to view this documentation in its full glory!

Depending on how you got the container (either by downloading from Dockerhub, or by manually building the container yourself), you need to start the container by mapping the containers' nginx port to your host. That would look something like this:

```bash
# start the container from Dockerhub with tcp/9999 opened on your host
docker run --rm -it -p 9999:80 leonjza/frida-boot
```

<details>
<summary>Building the container yourself (Click to expand)</summary>

If you would prefer to build the container yourself, you can do that with:

- `git clone https://github.com/leonjza/frida-boot`
- Make modifications as you wish `¯\_(ツ)_/¯`
- Decide on a name and tag for the container. I usually tag locally built images with `:local`.
- Build the image (from the projects root) with `docker build -t frida-boot:local .`

</details>

!> **Note** If you built the image yourself, you need to use the tag name you used in the `docker build` command to start the image.

In either case, the documetation server should be available on port `9999` (unless you change that ofc.).

## Ready for the next step

![frida-boot](_media/frida-boot-prompt.png)

If you can see the `frida-boot` prompt in your terminal and browse to <http://localhost:9999> then you are ready to continue! Head over to the [Environment](1-getting-started/quickstart) page!
