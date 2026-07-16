# Run the builder on the NATIVE build platform and cross-compile to the target arch.
# Without --platform=$BUILDPLATFORM, buildx pulls the builder image for the *target*
# arch and runs it under QEMU — on Apple Silicon building linux/amd64 this crashes
# `go mod download` (SIGSEGV). Cross-compiling natively (GOARCH below) avoids emulation.
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS builder
WORKDIR /src

ARG TARGETARCH

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -o /out/obo-observer .

FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /out/obo-observer /app/obo-observer

EXPOSE 8080
ENTRYPOINT ["/app/obo-observer"]
