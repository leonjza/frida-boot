FROM debian:bullseye-slim

LABEL maintainer="@leonjza"
LABEL github="https://github.com/leonjza/frida-boot"

# https://unix.stackexchange.com/a/480460
# We need those man pages for frida-trace
RUN sed -i '/path-exclude \/usr\/share\/man/d' /etc/dpkg/dpkg.cfg.d/docker && \
    sed -i '/path-exclude \/usr\/share\/groff/d' /etc/dpkg/dpkg.cfg.d/docker

RUN export DEBIAN_FRONTEND=noninteractive \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
    # course documentation \
    nginx-light \
    # frida and compiler stuff \
    python3-pip build-essential \
    # to debug stuff \
    gdb locales procps file ltrace \
    # so that frida-trace can populate args \
    man manpages-dev \
    # typescript \
    npm
    # utils
    git vim tmux curl \
  && rm -rf /var/lib/apt/lists/*

# Configure the locale for UTF8 support.
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Install Frida
RUN pip3 install frida-tools

# GEF Setup aka: Pretty debugging.
RUN curl -fsSL https://github.com/hugsy/gef/raw/master/gef.py -o ~/.gdbinit-gef.py && \
    echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# Configure the documentation
RUN rm -Rf /var/www/html
ADD course/ /var/www/html

# Add code snippets
ADD software /root/software

# Defaults
VOLUME /root/code
WORKDIR /root
RUN echo 'export PS1="\[\e[30;42m\]frida-boot\[\e[m\]:\w\\$ "' > ~/.bashrc

# nginx serving docs
EXPOSE 80

ADD docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
