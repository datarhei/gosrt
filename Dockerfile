ARG BUILD_IMAGE=golang:1.18.3-alpine3.16

FROM $BUILD_IMAGE as builder

COPY . /build

RUN cd /build/client && CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -a -o client .
RUN cd /build/server && CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -a -o server .

FROM scratch

COPY --from=builder /build/client/client /bin/srt-client
COPY --from=builder /build/server/server /bin/srt-server

WORKDIR /srt
