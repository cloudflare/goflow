ARG src_dir="/go/src/github.com/cloudflare/goflow"

FROM golang:alpine as builder
ARG src_dir

RUN apk --update --no-cache add git && \
    mkdir -p ${src_dir}

WORKDIR ${src_dir}
COPY . .

RUN go get -u github.com/golang/dep/cmd/dep && \
    dep ensure && \
    go build

FROM alpine:latest
ARG src_dir

RUN apk update --no-cache && \
    adduser -S -D -H -h / flow
USER flow
COPY --from=builder ${src_dir}/goflow /

ENTRYPOINT ["./goflow"]
