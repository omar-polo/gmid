FROM alpine as builder
WORKDIR /build
RUN apk update && apk upgrade && apk add alpine-sdk linux-headers libressl-dev flex bison libevent-dev libevent-static
COPY . .
RUN make static

FROM alpine
RUN apk update && apk upgrade
COPY --from=builder /build/gmid /bin/gmid
