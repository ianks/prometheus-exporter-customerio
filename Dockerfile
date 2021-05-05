FROM golang:1.14-alpine AS build

WORKDIR /src/
COPY main.go go.* /src/
RUN CGO_ENABLED=0 go build -o /bin/prometheus-exporter-customerio

FROM scratch
COPY --from=build /bin/prometheus-exporter-customerio /bin/prometheus-exporter-customerio
EXPOSE 8080
ENTRYPOINT ["/bin/prometheus-exporter-customerio"]