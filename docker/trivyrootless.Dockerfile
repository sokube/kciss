FROM ghcr.io/aquasecurity/trivy:0.19.2 AS trivy

FROM alpine:3.14
ARG UID="2000"
ARG GID="0"

RUN apk --no-cache add ca-certificates=20191127-r5 && \
    export GIDNAME=$(getent group $GID | cut -d':' -f1) && \
    adduser -S -u $UID -G "$GIDNAME" trivy
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
USER $UID

WORKDIR /home/trivy
ENTRYPOINT ["trivy"]
