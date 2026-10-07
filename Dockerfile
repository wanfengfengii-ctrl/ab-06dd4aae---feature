# syntax=docker/dockerfile:1

# ---- build stage: compile the static API binary ----
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# ---- runtime stage: minimal image, healthcheck via the binary itself ----
FROM scratch AS runtime
COPY --from=build /out/server /server
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/server"]

# ---- verify stage: one-shot test/build/smoke runner (see scripts/verify.sh) ----
FROM golang:1.24-alpine AS verify
WORKDIR /src
COPY . .
ENTRYPOINT ["sh", "scripts/verify.sh"]
