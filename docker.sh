#!/usr/bin/env bash
#
# 2020 @leonjza
#
# Part of the frida-boot workshop
#  https://github.com/leonjza/frida-boot

if ! hash docker 2>/dev/null; then
    echo "Docker is required. Please install it first!"
    exit 1
fi

if ! [[ "$1" =~ ^(pull|build|run|run-dev|shell)$ ]]; then
    echo "Usage: $0 [action]"
    echo " Actions can be: pull; build; run; run-dev; shell"
    exit 1
fi

case $1 in 

pull)
    echo "> pulling latest workshop image"
    docker pull leonjza/frida-boot
    ;;
build)
    echo "> building a local image"
    docker build -t frida-boot:local .
    ;;
run)
    echo "> starting a new container"
    echo
    docker run --cap-add SYS_PTRACE --rm -it --name frida-boot -p9999:80 \
        -v $(pwd)/code:/root/code leonjza/frida-boot
    ;;
run-dev)
    echo "> runing a content dev instance"
    echo "> webserver exposed on port 9999"
    docker run --cap-add SYS_PTRACE --rm -it --name frida-boot -p9999:80 \
        -v $(pwd)/code:/root/code \
        -v $(pwd)/course:/var/www/html frida-boot:local
    ;;
shell)
    echo "> spawning new shell in the frida-boot container"
    docker exec -it frida-boot /bin/bash
    ;;
esac
