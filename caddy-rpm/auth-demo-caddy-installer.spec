Name: auth-demo-caddy-installer
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
make caddy
cd common && make && cd -

%install
mkdir -p %{buildroot}/%{_datarootdir}/caddy %{buildroot}/%{_prefix}/etc %{buildroot}/%{_prefix}/bin %{buildroot}/usr/lib/systemd/system
cp -p caddy %{buildroot}/%{_prefix}/bin
cp -p caddy-server/Caddyfile common/public-key.pem %{buildroot}/%{_prefix}/etc
cp caddy-server.service %{buildroot}/usr/lib/systemd/system

%post
CADDY_SVR_USER="${CADDY_SVR_USER:-caddy-server}"
CADDY_SVR_GROUP="${CADDY_SVR_GROUP:-caddy-server}"
CADDY_SVR_HOME="${CADDY_SVR_HOME:-/home/caddy-server}"

if ! getent group "$CADDY_SVR_GROUP" >/dev/null ; then
    groupadd -f "$CADDY_SVR_GROUP" || exit 1
fi

if ! getent passwd "$CADDY_SVR_USER" >/dev/null ; then
    useradd -g "$CADDY_SVR_GROUP" -d "$CADDY_SVR_HOME" -s /sbin/nologin -c "caddy server owner" "$CADDY_SVR_USER" || exit 1
fi

systemctl daemon-reload

%files
%defattr(-,root,root,-)
/opt/auth-demo/bin/caddy
/opt/auth-demo/etc/Caddyfile
/usr/lib/systemd/system/caddy-server.service

%attr(440,root,caddy-server) /opt/auth-demo/etc/public-key.pem

