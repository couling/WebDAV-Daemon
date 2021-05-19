FROM debian:latest AS build_env
RUN apt-get update
RUN apt-get install --assume-yes --no-install-recommends gcc libmicrohttpd-dev libpam0g-dev libxml2-dev libgnutls28-dev uuid-dev


FROM build_env AS package_env
WORKDIR /root

RUN apt-get install --assume-yes --no-install-recommends wget ca-certificates
RUN wget https://github.com/couling/DPKG-Build-Tools/releases/download/v2.2/couling-package-project_2.2_all.deb
RUN apt-get install --assume-yes --no-install-recommends ./couling-package-project_2.2_all.deb fakeroot
RUN rm ./couling-package-project_2.2_all.deb
