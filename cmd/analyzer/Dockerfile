FROM golang:1.25 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/trufflehog-analyzer ./cmd/analyzer

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/trufflehog-analyzer /trufflehog-analyzer

ENV PORT=8080
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/trufflehog-analyzer"]
