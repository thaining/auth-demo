#!/bin/bash -x

DIRNAME="$(dirname $0)"

# Create repo
YUMREPO_PATH="${YUMREPO_PATH:-$(readlink -f ${DIRNAME}/../rpm-repo)}"
S3_BUCKET_NAME="${S3_BUCKET_NAME:-my-rpm-repo}"

cd "$YUMREPO_PATH"
for arch in x86_64 i386 noarch SRPMS;
do
    createrepo --deltas "$arch"
done

# Sync to S3
aws s3 sync --delete "$YUMREPO_PATH" s3://"$S3_BUCKET_NAME"/
