FROM debian:stretch

ARG DOWNLOAD_URL=https://github.com/cloudflare/goflow/releases/download/v2.0.0-pre1/goflow-linux-x86_64

RUN apt-get update && \
    apt-get -y install curl && \
    apt-get clean && \
    curl -L ${DOWNLOAD_URL} > /goflow && \
    chmod +x /goflow

ENTRYPOINT [ "/goflow" ]