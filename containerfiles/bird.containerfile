FROM alpine:latest
RUN apk add --no-cache bird2 supervisor
RUN mkdir -p /etc/bird
COPY supervisord-bird.conf /etc/supervisord.conf

CMD ["supervisord", "-c", "/etc/supervisord.conf", "-n"]
