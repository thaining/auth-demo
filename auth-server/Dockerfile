# Build node modules
FROM registry.access.redhat.com/ubi8/nodejs-16 as node-module-builder

ARG REFRESHED_ON=2023-03-10

COPY auth-server/package.json .
COPY auth-server/package-lock.json .

RUN /usr/bin/npm install && tar cvzf node_modules.tgz node_modules

FROM registry.access.redhat.com/ubi8/nodejs-16 as auth-server-run

USER root

# install EPEL to get supervisord
RUN /usr/bin/yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm

# install memcached and supervisor
RUN /usr/bin/dnf install -y memcached supervisor
RUN mkdir -p /var/log/supervisor && chown 1001:1001 /var/log/supervisor

# copy in the supervisor config
COPY auth-server/auth-server-supervisor.conf /etc/supervisord.d/auth-server.ini
RUN chmod 644 /etc/supervisord.d/auth-server.ini

WORKDIR /opt/app-root/src

COPY --from=node-module-builder /opt/app-root/src/node_modules.tgz .
RUN tar xvzf node_modules.tgz && rm node_modules.tgz
COPY --chown=default:root --from=node-module-builder /opt/app-root/src/package-lock.json .
COPY --chown=default:root auth-server/authServer.js .
COPY --chown=default:root auth-server/authPasswords.bcup .
COPY --chown=default:root common/private-key.pem .
COPY --chown=default:root common/public-key.pem .
COPY --chown=default:root auth-server/dockerConfig.json .
RUN chmod -R ga-w node_modules authServer.js authPasswords.bcup public-key.pem private-key.pem dockerConfig.json

FROM auth-server-run

USER default

ARG AUTH_SERVER_WORKDIR=/opt/app-root/src
ENV AUTH_SERVER_WORKDIR=$AUTH_SERVER_WORKDIR
ENV AUTH_SERVER_LOGDIR=/var/log/supervisor
ENV AUTH_BCUP_FILE_NAME=$AUTH_SERVER_WORKDIR/authPasswords.bcup

CMD ["/usr/bin/supervisord"]
