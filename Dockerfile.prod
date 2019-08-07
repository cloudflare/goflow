ARG src_uri=github.com/cloudflare/goflow

FROM golang:alpine as builder
ARG src_uri

RUN apk --update --no-cache add git && \
    go get -u $src_uri

FROM alpine:latest
ARG src_uri

RUN apk update --no-cache && \
    adduser -S -D -H -h / flow
USER flow
COPY --from=builder /go/bin/goflow /

ENTRYPOINT ["./goflow"]
