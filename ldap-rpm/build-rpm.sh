#!/bin/bash -x

TOPDIR="${TOPDIR:-${PWD}/rpm}"
AUTH_DEMO_VERSION="${AUTH_DEMO_VERSION:-1.0.1}"
LDAP_RPM_BUILD="${LDAP_RPM_BUILD:-7}"
AUTH_DEMO_PREFIX="${AUTH_DEMO_PREFIX:-/opt/auth-demo}"

rpmbuild -bb --build-in-place auth-demo-ldap-installer.spec \
         --define "_topdir ${TOPDIR}" \
         --define "_version ${AUTH_DEMO_VERSION}" \
         --define "_build_number ${LDAP_RPM_BUILD}" \
         --define "_prefix ${AUTH_DEMO_PREFIX}"
rc=$?

if [ $rc -ne 0 ]; then
    echo >&2 "ERROR($rc): $0 failed. spec file is in ${PWD}/auth-demo-ldap-installer.spec"
    exit $rc
fi

mv rpm/RPMS/*/*.rpm .
rm -rf rpm
