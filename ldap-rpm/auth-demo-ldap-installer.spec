Name: auth-demo-ldap-installer
License: MIT
Summary: Customizes OpenLDAP installation for auth-demo
Version: %{_version}
Release: %{_build_number}
BuildArch: noarch

Requires: openldap openldap-clients openldap-servers

%description
OpenLDAP setup tool for auth-demo

%prep

%build

%install
mkdir -p %{buildroot}/%{_bindir} %{buildroot}/%{_prefix}/etc
install -m 0755 setup-ldap.sh %{buildroot}/%{_bindir}/setup-ldap.sh

%files
%defattr(-,root,root,-)
%{_bindir}/setup-ldap.sh
%{_prefix}/etc

%changelog
