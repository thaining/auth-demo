#!/bin/bash -x

TOPDIR="${TOPDIR:-${PWD}/rpm}"
AUTH_DEMO_VERSION="${AUTH_DEMO_VERSION:-1.0.1}"
AUTH_RPM_BUILD="${AUTH_RPM_BUILD:-8}"
AUTH_DEMO_PREFIX="${AUTH_DEMO_PREFIX:-/opt/auth-demo}"
AUTH_DEMO_SHELL="${AUTH_DEMO_SHELL:-/bin/bash}"

rpmbuild -bb --build-in-place auth-demo-auth-installer.spec \
         --define "_topdir ${TOPDIR}" \
         --define "_version ${AUTH_DEMO_VERSION}" \
         --define "_build_number ${AUTH_RPM_BUILD}" \
         --define "_prefix ${AUTH_DEMO_PREFIX}" \
         --define "_buildshell ${AUTH_DEMO_SHELL}"
rc=$?

if [ $rc -ne 0 ]; then
    echo >&2 "ERROR($rc): $0 failed. spec file is in ${PWD}/auth-demo-auth-installer.spec"
    exit $rc
fi

mv rpm/RPMS/*/*.rpm .
rm -rf rpm
