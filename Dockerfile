FROM golang:alpine
ENV CGO_ENABLED 0
RUN apk add --update ca-certificates alpine-sdk
COPY . /build
WORKDIR /build
RUN make

FROM scratch
MAINTAINER Thomas Maurice <thomas@maurice.fr>
COPY --from=0 /build/bin/server /server
# probably dont need the cli here
# COPY --from=0 /build/bin/cli /cli
COPY --from=0 /etc/ca-certificates /etc/ca-certificates
