FROM gsoci.azurecr.io/giantswarm/golang:1.24

LABEL "com.github.actions.name"="nancy-fixer-action"
LABEL "com.github.actions.description"="runs nancy-fixer to patch vulnerabilities found by Nancy"
LABEL "com.github.actions.icon"="shield"
LABEL "com.github.actions.color"="orange"
LABEL "repository"="https://github.com/giantswarm/nancy-fixer"

ADD https://github.com/sonatype-nexus-community/nancy/releases/download/v1.0.48/nancy-v1.0.48-linux-amd64 /usr/local/bin/nancy
RUN chmod a+x /usr/local/bin/nancy

ADD nancy-fixer /usr/local/bin/nancy-fixer

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV GOFLAGS=-buildvcs=false

ENV LOG_LEVEL=info

ENTRYPOINT ["/entrypoint.sh"]
