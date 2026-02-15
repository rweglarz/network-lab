FROM alpine:latest
RUN apk add --no-cache \
    bash \
    bird2 \
    fping \
    iproute2 \
    supervisor \
    tcpdump \
    traceroute
RUN mkdir -p /etc/bird
COPY supervisord-bird.conf /etc/supervisord.conf

CMD ["supervisord", "-c", "/etc/supervisord.conf", "-n"]
