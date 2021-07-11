FROM alpine as builder
WORKDIR /build
RUN apk update &&	\
	apk upgrade &&	\
	apk add	--repository=https://dl-cdn.alpinelinux.org/alpine/edge/main \
		alpine-sdk	\
		linux-headers	\
		bison		\
		libretls-dev	\
		libretls-static	\
		libevent-dev	\
		libevent-static
COPY . .
RUN make static

FROM alpine
RUN apk update && apk upgrade
COPY --from=builder /build/gmid /bin/gmid
ENTRYPOINT ["gmid"]
