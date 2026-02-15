FROM alpine:latest
RUN apk add --no-cache \
    bash \
    frr \
    fping \
    iproute2 \
    supervisor \
    tcpdump \
    traceroute
RUN sed -i 's/bgpd=no/bgpd=yes/' /etc/frr/daemons && \
    sed -i 's/zebra=no/zebra=yes/' /etc/frr/daemons
COPY supervisord-frr.conf /etc/supervisord.conf

CMD ["supervisord", "-c", "/etc/supervisord.conf", "-n"]

