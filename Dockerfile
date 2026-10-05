# syntax=docker/dockerfile:1
ARG GO_VERSION=1.26.6
FROM golang:${GO_VERSION} AS build
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X github.com/Bugs5382/go-buildinfo.Version=${VERSION} -X github.com/Bugs5382/go-buildinfo.Commit=${COMMIT}" -o /out/connector ./cmd/connector

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/connector /connector
USER nonroot:nonroot
ENTRYPOINT ["/connector"]
