FROM golang:1.26.4-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

FROM scratch AS server
COPY --from=build /out/server /server
COPY rules /rules
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]
CMD ["-rules", "/rules/fingerprints.json"]

FROM scratch AS client
COPY --from=build /out/client /client
USER 65532:65532
ENTRYPOINT ["/client"]
