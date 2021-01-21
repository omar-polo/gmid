FROM alpine as builder
WORKDIR /build
RUN apk update && apk upgrade && apk add alpine-sdk linux-headers libressl-dev flex bison
COPY . .
RUN make clean gmid

FROM alpine
RUN apk update && apk upgrade && apk add libressl
COPY --from=builder /build/gmid /bin/gmid
ENTRYPOINT /bin/gmid
