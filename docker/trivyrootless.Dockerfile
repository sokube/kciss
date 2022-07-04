ARG TRIVY_VERSION=0.27.0
ARG ALPINE_VERSION=3.14.2

FROM ghcr.io/aquasecurity/trivy:$TRIVY_VERSION AS trivy

FROM alpine:$ALPINE_VERSION
ARG UID="2000"
LABEL org.opencontainers.image.source="https://github.com/sokube/kciss"
LABEL org.opencontainers.image.authors="Sokube SA"

RUN apk --no-cache add ca-certificates=20191127-r5 && \
    adduser -S -u $UID -G root trivy
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
USER $UID

WORKDIR /home/trivy
ENTRYPOINT ["trivy"]
