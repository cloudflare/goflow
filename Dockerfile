FROM golang:alpine as builder
ARG LDFLAGS=""

RUN apk --update --no-cache add git build-base gcc

COPY . /build
WORKDIR /build

RUN go build -ldflags "${LDFLAGS}" -o goflow cmd/goflow/goflow.go

FROM alpine:latest
ARG src_dir

RUN apk update --no-cache && \
    adduser -S -D -H -h / flow
USER flow
COPY --from=builder /build/goflow /

ENTRYPOINT ["./goflow"]
