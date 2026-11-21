FROM golang:1.22-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY go.mod ./
COPY *.go ./
COPY static ./static
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o ru-proxy-pool .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S app && adduser -S -G app -H -s /sbin/nologin app \
 && mkdir -p /app/data && chown app:app /app/data && chmod 700 /app/data
WORKDIR /app
COPY --from=builder /app/ru-proxy-pool /app/ru-proxy-pool
COPY certs ./certs
# Сервис работает от непривилегированного пользователя
USER app
ENV DATA_FILE=/app/data/pool.json CERTS_DIR=/app/certs
EXPOSE 8080
CMD ["/app/ru-proxy-pool"]
