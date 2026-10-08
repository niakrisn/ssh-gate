FROM golang:1.26-bookworm

# dpkg-buildpackage lives in dpkg-dev, dh in debhelper, and dpkg expects
# build-essential in any build environment. man-db is what lets dh_installman
# render debian/ssh-gate.1 and fail the build on a roff error instead of
# shipping a page that man(1) cannot show. Nothing else is needed: the compile
# step in debian/rules uses the Go toolchain already in the base image, and the
# unit file plus the systemd maintainer snippets are handled by debhelper itself.
RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential dpkg-dev debhelper man-db \
	&& rm -rf /var/lib/apt/lists/*
