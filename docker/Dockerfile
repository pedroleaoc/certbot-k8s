# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

ARG NGINX_BASEIMAGE="nginx:1.21.6"
ARG VERRION="latest"

FROM $NGINX_BASEIMAGE

ENV IMAGE_VERSION="$VERSION"

# certbot also requires tzdata, and we need to set up the localtime for that
# so we can install certbot without any issues / interrupts.
RUN apt update &&\
    ln -fs /usr/share/zoneinfo/Europe/London /etc/localtime &&\
    DEBIAN_FRONTEND=noninteractive apt install -y certbot
