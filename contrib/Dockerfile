FROM alpine
WORKDIR /build
RUN apk update &&	\
	apk upgrade &&	\
	apk add	--repository=https://dl-cdn.alpinelinux.org/alpine/edge/main \
		alpine-sdk	\
		linux-headers	\
		bison		\
		libevent-dev 	\
		openssl-dev
COPY . .
RUN ./configure && make && make install
RUN adduser -H -S -s /sbin/nologin gmid
RUN mkdir /var/gemini
RUN ./contrib/gencert -e localhost && \
	mv localhost.pem /etc/ssl && \
	mv localhost.key /etc/ssl/private
RUN mv contrib/Docker.gmid.conf /etc/gmid.conf
ENTRYPOINT ["gmid", "-f"]
