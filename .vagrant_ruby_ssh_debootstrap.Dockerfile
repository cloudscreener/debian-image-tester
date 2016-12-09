# -*- mode:dockerfile;tab-width:2;indent-tabs-mode:nil;coding:utf-8 -*-
# vim: ft=sh syn=sh fileencoding=utf-8 sw=2 ts=2 ai eol et si
#
# vagrant_ruby_ssh_debootstrap.Dockerfile: Debian base + SSH + debootstrap
#                                          Vagrant Dockerfile
# (c) 2015 CloudScreener SAS, MIT License (see LICENSE file)
#
# Authors:
#   Laurent Vallar <laurent@cloudscreener.com>

FROM debian:jessie
MAINTAINER Laurent Vallar "laurent@cloudscreener.com"
LABEL Description="Debian base + Ruby" Vendor="CloudScreener" Version="1.0"

ARG DEB_DIST

# Tell debconf to run in non-interactive mode
ENV DEBIAN_FRONTEND noninteractive

# Set neutral language
ENV LC_ALL C
ENV LANG C

# Fix TERM
ENV TERM linux

# Set some build environment variables
ENV DEB_MIRROR http://httpredir.debian.org/debian/
ENV DEB_SECURITY_MIRROR http://security.debian.org/
ENV DEB_COMPONENTS main

# Initialize sources.list, update all & install OpenSSH server
RUN echo "deb $DEB_MIRROR $DEB_DIST $DEB_COMPONENTS" \
      > /etc/apt/sources.list && \
    echo "deb $DEB_SECURITY_MIRROR $DEB_DIST/updates $DEB_COMPONENTS" \
      >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get -y upgrade && \
    apt-get -y dist-upgrade && \
    apt-get install -y ruby ruby-net-ssh pry \
                       openssh-client sudo \
                       debootstrap && \
    apt-get -y autoremove && \
    apt-get clean

# Set Timezone
RUN echo "Etc/UTC" > /etc/timezone && dpkg-reconfigure -f noninteractive tzdata

# Cleanups
RUN rm -rf /tmp/* /var/tmp/*

# Create and configure vagrant user
RUN useradd -m vagrant -s /bin/bash && \
  ( echo "vagrant:vagrant" | chpasswd ) && \
    adduser vagrant sudo && \
    /bin/echo -e "\nvagrant ALL=(ALL) NOPASSWD: ALL\n" >> /etc/sudoers && \
    install -o vagrant -g vagrant /dev/null /home/vagrant/.Xauthority && \
    install -o vagrant -g vagrant -m 700 -d /home/vagrant/.ssh

# Add unsecure Vagrant key
ENV VAGRANT_UNSECURE_SSH_KEY \
https://raw.githubusercontent.com/mitchellh/vagrant/master/keys/vagrant
ADD $VAGRANT_UNSECURE_SSH_KEY /home/vagrant/.ssh/id_rsa
ADD ${VAGRANT_UNSECURE_SSH_KEY}.pub /home/vagrant/.ssh/id_rsa.pub
RUN /bin/echo -e "Host *\n  StrictHostKeyChecking no\n  IdentityFile ~/.ssh/id_rsa" \
  > /home/vagrant/.ssh/config
RUN chmod 0600 /home/vagrant/.ssh/id_rsa && \
    chmod 0644 /home/vagrant/.ssh/id_rsa.pub && \
    chown vagrant.vagrant -R /home/vagrant/.ssh
