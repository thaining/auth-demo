#!/bin/bash

#
# a script to handle all the details of actually build caddy
# either in a Dockerfile or using a factory docker container
#

help() {
    echo "Syntax: $0 [-c <dest>] [-u <uid>] [-g <gid>]"
    echo "Options:"
    echo "-c     Copy caddy to to the dest directory after building"
    echo "-u     Change the uid of caddy to uid before copying"
    echo "-g     Change the gid of caddy to gid before copying"
    echo "-v     Caddy version to build"
    echo "-h     Print this message"
}

check_dest() {
    if [ -d "$1" ] || [ -d "$(dirname "$1")" ]; then
        return
    fi

    help;
    exit 1;
}

uid=$(id -u)
gid=$(id -g)
chown="0"
copy="0"
version="2.6.4"

while [ $# -gt 0 ]; do
    cmd=$1
    case "$cmd" in
        -c|--copy)    dest=$2; check_dest $dest; copy="1"; shift;;
        -u|--uid)     uid=$2; chown="1"; shift;;
        -g|--gid)     gid=$2; chown="1"; shift;;
        -v|--version) version=$2; shift;;
        -h|--help)  help; exit 0;;
        *) echo "invalid argument"; help; exit 1;;
    esac
    shift
done

xcaddy build --with github.com/greenpau/caddy-security "v${version}"

if [ -n "$uid" ] || [ -n "$gid" ] && [ "$chown" == "1" ]; then
    chown ${uid}:${gid} ./caddy
fi

if [ "$copy" == "1" ]; then
    cp -p ./caddy "$dest"
fi
