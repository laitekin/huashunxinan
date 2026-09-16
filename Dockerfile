# Compile both programs in one cached build stage. CGO is disabled so the
# resulting binaries can run in minimal scratch images without libc.
FROM golang:1.26.4-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

FROM scratch AS server
COPY --from=build /out/server /server
# Keep a rule copy in the image so it also works without the Compose bind mount.
COPY rules /rules
# 65532 is a conventional unprivileged UID/GID and does not require /etc/passwd.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]
CMD ["-rules", "/rules/fingerprints.json"]

FROM scratch AS client
COPY --from=build /out/client /client
USER 65532:65532
ENTRYPOINT ["/client"]
