FROM almalinux:latest AS build_env
RUN dnf -y update
RUN dnf -y install git rpm-build "dnf-command(builddep)"
WORKDIR /root
RUN git clone https://github.com/sbluhm/WebDAV-Daemon.git
RUN dnf -y builddep --enablerepo="crb" WebDAV-Daemon/package-control/webdavd.spec
RUN mkdir -p ~/rpmbuild/SOURCES
RUN export version=`grep Version WebDAV-Daemon/package-control/webdavd.spec | awk '{print  $2}'` \
    && cp -r WebDAV-Daemon WebDAV-Daemon-${version} \
    && tar czf ~/rpmbuild/SOURCES/v${version}.tar.gz WebDAV-Daemon-${version}
RUN rpmbuild -ba WebDAV-Daemon/package-control/webdavd.spec
RUN rm -Rf WebDAV-Daemon*
RUN dnf -y remove git rpm-build git libuuid-devel libxml2-devel pam-devel

FROM build_env AS package_env
WORKDIR /root
RUN dnf -y install ~/rpmbuild/RPMS/x86_64/webdavd-*.rpm
