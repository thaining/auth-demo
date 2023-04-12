#!/bin/bash -x

BUILD_CMD="/common/caddy-build.sh"

help() {
    echo "Syntax: $0 [-C <build command path>] [-- <build command arguments>]"
    echo "Options:"
    echo "-C     Set the command used to complete the caddy build -- default: /common/caddy-build.sh"
    echo "--     Pass all subsequent arguments to the build command"
    echo "-h     Print this message"
}


while [ $# -gt 0 ]; do
    cmd=$1
    case "$cmd" in
        -C|--command)   BUILD_CMD=$2; shift;;
        --)             shift; break;;
        -h|--help)      help; exit 0;;
        *) echo "invalid argument"; help; exit 1;;
    esac
    shift
done


# amazonlinux needs to run with "--securityopt seccomp=unconfined" in order to install packages
# that flag is not supported with "docker build", so building up of the amazonlinux docker build enviroment
# needs to take place at runtime

# this is included to be sure we identify what distro is running.
IDSTRING="${IDSTRING:-unknown_distro}"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        rhel|ol)
            DISTRO_VER="$(echo $VERSION_ID | cut -d'.' -f1)"
            IDSTRING="rhel${DISTRO_VER}"
            ;;
        amzn)
            IFS=':' read -a CPE <<< "$CPE_NAME"
            if [ "${CPE[*]:2:2}" = "amazon linux" ]; then
                DISTRO_VER=1
            elif [ "${CPE[*]:4:2}" = "amazon_linux 2" ]; then
                DISTRO_VER=2
            else
                DISTRO_VER="$VERSION_ID"
            fi
            IDSTRING="amzn${DISTRO_VER}"
            ;;
        centos)
            DISTRO_VER="$(echo $VERSION_ID | cut -d'.' -f1)"
            IDSTRING="el${DISTRO_VER}"
            ;;
        ubuntu)
            UBVERSION="$(echo $VERSION_ID | cut -d'.' -f1)"
            IDSTRING="ub${UBVERSION}"
            ;;
        *)
            VERSION_DATA="$PRETTY_NAME ($VERSION)"

            if [ -e /etc/redhat-release ]; then
                DISTRO_VER="$(grep -Eow '([0-9\.]+)' /etc/redhat-release | cut -d'.' -f1)"
                if grep -q 'Red Hat' /etc/redhat-release; then
                    IDSTRING="rhel${DISTRO_VER}"
                elif grep -q CentOS /etc/redhat-release; then
                    IDSTRING="el${DISTRO_VER}"
                fi
            else
                VERSION_DATA="$(cat /etc/*-release)"
            fi

            if [ "$IDSTRING" = "unknown_distro" ]; then
                echo "Unknown operating system version: $VERSION_DATA"
            fi
            ;;
    esac
fi

case "$IDSTRING" in
    amzn2023)
        cd
        yum install -y golang
        go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
        PATH=${PATH}:${PWD}/go/bin
        export PATH
        ls -l ${PWD}/go/bin
        ;;
    *)
        echo "Unsupported OS.  Doing nothing."
        ;;
esac

"$BUILD_CMD" $@
