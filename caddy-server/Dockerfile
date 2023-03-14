# Build image
FROM registry.access.redhat.com/ubi8/go-toolset as caddy-builder

ARG REFRESHED_ON=2023-03-09

USER root

ARG CADDY_VERSION=2.6.4
ENV CADDY_VERSION=$CADDY_VERSION

SHELL [ "/bin/bash", "-c" ]
WORKDIR /opt/app-root/src

RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
COPY common/caddy-build.sh .

RUN PATH=${PATH}:${PWD}/go/bin ./caddy-build.sh -v $CADDY_VERSION

FROM registry.access.redhat.com/ubi8/ubi:8.4 as caddy-run-base

USER root

RUN yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
RUN dnf install -y tini
RUN useradd -c "caddy software owner" -d "/home/caddy-owner" -m -s /usr/sbin/nologin -U caddy-owner

COPY --from=caddy-builder /opt/app-root/src/caddy /usr/bin

RUN /usr/bin/caddy list-modules

VOLUME ["/www"]
WORKDIR /www

RUN mkdir /etc/caddy && chmod 755 /etc/caddy
COPY caddy-server/Caddyfile /etc/caddy/Caddyfile
COPY common/public-key.pem /etc/caddy
RUN chmod 644 /etc/caddy/*

COPY caddy-server/index.md /www/index.md
RUN chmod 755 /www && chmod 644 /www/*

FROM caddy-run-base

USER caddy-owner

ENV JWT_SHARED_KEY=/etc/caddy/public-key.pem
ENV AUTH_SERVER_PROXY_HOST=auth-server
ENV AUTH_SERVER_PROXY_PORT=12123

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile"]
