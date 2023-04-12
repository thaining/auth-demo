#!/bin/bash

#
# a script to handle all the details of building npm modules
# either in a Dockerfile or using a factory docker container
#

help() {
    echo "Syntax: $0 [-c <dest>] [-u <uid>] [-g <gid>] -s <source directory>"
    echo "Options:"
    echo "-d     Copy the output tar file to to the dest directory after building"
    echo "-s     Source directory for files used to complete the build"
    echo "-v     The number of the version of nodejs to be used to build modules"
    echo "-u     Change the uid of the tar file to uid before copying"
    echo "-g     Change the gid of the tar file to gid before copying"
    echo "-h     Print this message"
}

check_dir() {
    if [ -d "$1" ] || [ -d "$(dirname "$1")" ]; then
        return
    fi

    echo "Path ${1} is not a directory"
    help
    exit 1
}

check_version() {
    re='^[0-9]+$'

    if ! [[ ${1} =~ $re ]] ; then
        echo "Version number ${1} is not a number"
        help
        exit 1
    fi

    if [ ! "$1" -le "9" ]; then
        echo "Version number ${1} is too old a version"
        help
        exit 1
    fi
}

uid=$(id -u)
gid=$(id -g)
chown="0"
copy="0"
source="0"
version="18"

if [ $# = "0" ]; then
    echo "No source directory provided"
    help
    exit 1;
fi

while [ $# -gt 0 ]; do
    cmd=$1
    case "$cmd" in
        -d|--dest)    dest=$2; check_dir "$dest"; copy="1"; shift;;
        -s|--source)  src=$2; check_dir "$src"; source="1"; shift;;
        -v|--version) node_version=$2; shift;;
        -u|--uid)     uid=$2; chown="1"; shift;;
        -g|--gid)     gid=$2; chown="1"; shift;;
        -h|--help)  help; exit 0;;
        *) echo "invalid argument"; help; exit 1;;
    esac
    shift
done

if [ "0" = "$source" ]; then
    echo "No source directory specified"
    echo "Exiting..."
    help
    exit 1
fi

if [ "0" = "$copy" ]; then
    echo "No destination directory specified"
    echo "Exiting..."
    help
    exit 1
fi

for file in "${src}/package.json" "${src}/package-lock.json"; do
    if [ ! -f "$file" ]; then
        echo "${file} is not found"
        echo "Exiting..."
        exit 1
    fi
done

# make sure the necessary developer tools are installed, just to be safe
yum makecache
yum install -y gcc-c++ make tar gzip

yum install -y nodejs

cp "${src}"/package.json .
cp "${src}"/package-lock.json .

/usr/bin/npm install && tar cvzf node_modules.tgz node_modules

if [ -n "$uid" ] || [ -n "$gid" ] && [ "$chown" == "1" ]; then
    chown ${uid}:${gid} ./node_modules.tgz
fi

cp -p ./node_modules.tgz "$dest"
