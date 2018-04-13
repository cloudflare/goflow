FROM debian:stretch

ARG DOWNLOAD_URL=https://github.com/cloudflare/goflow/releases/download/v2.0.1/goflow-v2.0.1-linux-x86_64

RUN apt-get update && \
    apt-get -y install curl && \
    apt-get clean && \
    curl -L ${DOWNLOAD_URL} > /goflow && \
    chmod +x /goflow

ENTRYPOINT [ "/goflow" ]