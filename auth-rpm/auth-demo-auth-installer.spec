Name: auth-demo-auth-installer
License: MIT
Summary: Customizes OpenLDAP installation for auth-demo
Version: %{_version}
Release: %{_build_number}
BuildArch: x86_64

Requires: memcached npm nodejs

# I built this on Ubuntu 18, which brings dtrace along with bash/env -- which is
# not needed on amzn2023
%define __requires_exclude /usr/sbin/dtrace

%description
nodejs auth microservice setup tool for auth-demo

%prep

%build
make node_modules.tgz
cd common && make && cd -

%install
mkdir -p %{buildroot}/%{_datarootdir}/auth-server %{buildroot}/%{_prefix}/etc %{buildroot}/usr/lib/systemd/system
fakeroot tar xvzf node_modules.tgz -C %{buildroot}/%{_datarootdir}/auth-server
cp -p auth-server/authServer.js auth-server/authPasswords.bcup common/private-key.pem common/public-key.pem %{buildroot}/%{_datarootdir}/auth-server
cp auth-server.service %{buildroot}/usr/lib/systemd/system

%post
AUTH_SVR_USER="${AUTH_SVR_USER:-auth-server}"
AUTH_SVR_GROUP="${AUTH_SVR_GROUP:-auth-server}"
AUTH_SVR_HOME="${AUTH_SVR_HOME:-/home/auth-server}"

if ! getent group "$AUTH_SVR_GROUP" >/dev/null ; then
    groupadd -f "$AUTH_SVR_GROUP" || exit 1
fi

if ! getent passwd "$AUTH_SVR_USER" >/dev/null ; then
    useradd -g "$AUTH_SVR_GROUP" -d "$AUTH_SVR_HOME" -s /sbin/nologin -c "auth server owner" "$AUTH_SVR_USER" || exit 1
fi

systemctl daemon-reload

%files
%defattr(-,root,root,-)
/opt/auth-demo/share/auth-server/authServer.js
/opt/auth-demo/share/auth-server/authPasswords.bcup
/opt/auth-demo/share/auth-server/public-key.pem
/opt/auth-demo/share/auth-server/node_modules/
/usr/lib/systemd/system/auth-server.service

%attr(440,root,auth-server) /opt/auth-demo/share/auth-server/private-key.pem
