FROM centos:7

LABEL maintainer="aloaugus@cisco.com"

RUN yum install -y epel-release && \
    curl -s https://packagecloud.io/install/repositories/fdio/release/script.rpm.sh | bash && \
    yum install -y vpp vpp-debuginfo vpp-plugins

ADD vpp-manager /

ENTRYPOINT ["/vpp-manager"]
