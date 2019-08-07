FROM ruby

RUN apt-get update && \
    apt-get install -y git make rpm golang && \
    gem install fpm

WORKDIR /work

ENTRYPOINT [ "/bin/bash" ]
