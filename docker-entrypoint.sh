#!/bin/bash
if [ -e /var/run/nginx.pid ]; then echo "nginx is already running"; else nginx; fi

/bin/bash
