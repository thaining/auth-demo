.PHONY: clean default

#
# This uses the amazonlinux:2023 docker container pulled from Amazon ECR Public
# for more information see: https://docs.aws.amazon.com/linux/al2023/ug/install-docker.html
#

SHELL=/bin/bash

DOCKER_SECURITY_FLAGS = --security-opt seccomp=unconfined
DOCKER_CONTAINER = public.ecr.aws/amazonlinux/amazonlinux:2023
DOCKER_MOUNTS := -v "${PWD}":"/src":ro -v "${PWD}/common:/common" -v "${PWD}":"/dest"
CURRENT_UID := $(shell id -u)
CURRENT_GID := $(shell id -g)
CADDY_VERSION = 2.6.4

.DEFAULT: caddy

caddy: common/caddy-build.sh
	docker run --rm $(DOCKER_MOUNTS) $(DOCKER_SECURITY_FLAGS) $(DOCKER_CONTAINER) /src/caddy-build-wrapper.sh -- -c /dest -v $(CADDY_VERSION) -u $(CURRENT_UID) -g $(CURRENT_GID)

clean:
	rm -f caddy
