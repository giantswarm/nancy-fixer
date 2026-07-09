FROM gsoci.azurecr.io/giantswarm/golang:1.26.5

ARG TARGETARCH

LABEL "com.github.actions.name"="nancy-fixer-action"
LABEL "com.github.actions.description"="runs nancy-fixer to patch vulnerabilities found by Nancy"
LABEL "com.github.actions.icon"="shield"
LABEL "com.github.actions.color"="orange"
LABEL "repository"="https://github.com/giantswarm/nancy-fixer"

# repo: sonatype-nexus-community/nancy
ARG NANCY_VERSION=v2.1.0
RUN curl -sSLf https://github.com/sonatype-nexus-community/nancy/releases/download/${NANCY_VERSION}/nancy-${NANCY_VERSION}-linux-${TARGETARCH} -o /usr/local/bin/nancy \
  && chmod a+x /usr/local/bin/nancy

COPY nancy-fixer-linux-${TARGETARCH} /usr/local/bin/nancy-fixer

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV GOFLAGS=-buildvcs=false

ENV LOG_LEVEL=info

ENTRYPOINT ["/entrypoint.sh"]
