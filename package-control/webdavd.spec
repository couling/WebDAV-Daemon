Name:		webdavd
Version:	1.1
Release:        2%{?dist}
Summary:	Webdav based file server using PAM authentication
License:	MIT License

Source0:	https://github.com/couling/WebDAV-Daemon/archive/v%{version}.tar.gz

BuildRequires:	gcc
BuildRequires:  gnutls-devel
BuildRequires:  libmicrohttpd-devel
BuildRequires:  libxml2-devel
BuildRequires:  pam-devel
BuildRequires:	libuuid-devel
BuildRequires:	make

Requires:	gnutls
Requires:	libmicrohttpd
Requires:	libxml2
Requires:	pam
Requires:	libuuid
Requires:       mailcap

%description
webdavd is a WebDAV server designed to be a replace for SMBA providing access to a system's files without taking ownership of them. It aims to differ from most WebDAV servers on a number of points:

-    Users are authenticated through PAM and are always operating system users.
-    The webserver switches OS user to match the authenticated user before accessing any files.
-    The daemon operates without any prior knowledge of the files it's serving.
-    The daemon does NOT take ownership of the files it modifies and serves. It does not take ownership of any files in any way. Even locking operations are implemented using the native OS flock() function.

%global debug_package %{nil}
%define logfile %{_localstatedir}/log/%{name}/%{name}.log

%prep
%setup -n WebDAV-Daemon-%{version}

%build
%make_build

%install
install -Dpm 755 build/webdavd %{buildroot}%{_sbindir}/webdavd
install -Dpm 755 build/rap %{buildroot}%{_prefix}/lib/webdavd/webdav-worker
install -Dpm 644 package-with/pam-rhel.conf %{buildroot}%{_sysconfdir}/pam.d/webdavd
install -Dpm 644 package-with/conf.xml %{buildroot}%{_sysconfdir}/webdavd
install -d %{buildroot}%{_datadir}/webdavd
install -Dpm 644 package-with/share/* %{buildroot}%{_datadir}/webdavd
install -Dpm 644 package-with/systemd.service %{buildroot}%{_prefix}/lib/systemd/system/webdavd.service
install -Dpm 644 package-with/logrotate.conf %{buildroot}%{_sysconfdir}/logrotate.d/webdavd


%post
%systemd_post %{name}.service

%files
%{_sbindir}/webdavd
%{_prefix}/lib/webdavd/webdav-worker
%{_datadir}/webdavd/*
%{_prefix}/lib/systemd/system/webdavd.service
%config(noreplace) %{_sysconfdir}/pam.d/webdavd
%config(noreplace) %{_sysconfdir}/webdavd
%config(noreplace) %{_sysconfdir}/logrotate.d/webdavd

%preun
%systemd_preun %{name}.service

%postun

%changelog
* Sat Oct 14 2023 Stefan Bluhm <stefan.bluhm@clacee.eu> - 1.1-2
- Don't replacing existing config files when installing/updating the package.

* Fri Sep 18 2020 Stefan Bluhm <stefan.bluhm@clacee.eu> - 1.1-1
- Initial package based on webdavd version 1.1 available at https://github.com/couling/WebDAV-Daemon
