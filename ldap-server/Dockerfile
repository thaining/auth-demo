FROM bitnami/openldap:latest as builder

USER root
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

COPY stage2.sh /opt/bitnami/scripts
RUN chmod 644 /opt/bitnami/scripts/stage2.sh
RUN chown root:root /opt/bitnami/scripts/stage2.sh

COPY setup.sh /tmp
RUN cat /tmp/setup.sh >> /opt/bitnami/scripts/openldap/setup.sh
RUN rm /tmp/setup.sh

FROM builder

USER 1001
ENTRYPOINT [ "/opt/bitnami/scripts/openldap/entrypoint.sh" ]
CMD [ "/opt/bitnami/scripts/openldap/run.sh" ]