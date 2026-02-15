FROM golang:alpine AS builder
RUN apk add --no-cache git
RUN go install github.com/osrg/gobgp/v3/cmd/gobgp@latest
RUN go install github.com/osrg/gobgp/v3/cmd/gobgpd@latest

FROM alpine:latest
RUN apk add --no-cache \
    bash \
    fping \
    iproute2 \
    supervisor \
    tcpdump \
    traceroute
COPY --from=builder /go/bin/gobgp /usr/local/bin/
COPY --from=builder /go/bin/gobgpd /usr/local/bin/
COPY supervisord-gobgp.conf /etc/supervisord.conf

CMD ["supervisord", "-c", "/etc/supervisord.conf", "-n"]
