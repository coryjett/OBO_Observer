FROM golang:1.22-alpine AS builder
WORKDIR /src

# Use build platform (e.g. arm64 on Apple Silicon) so the binary matches the cluster.
ARG TARGETARCH

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -o /out/obo-observer .

FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /out/obo-observer /app/obo-observer

EXPOSE 8080
ENTRYPOINT ["/app/obo-observer"]
