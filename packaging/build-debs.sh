#!/usr/bin/env bash
# Build ssh-gate .deb packages from source with the distribution's own tooling:
# dpkg-buildpackage driving debhelper through debian/rules.
#
# The build runs in Docker because this machine is not a Debian box. One builder
# image (packaging/Dockerfile.builder: Debian userland plus a Go toolchain new
# enough for go.mod) produces a package per target distribution. The binary is a
# static Go executable, so the target distribution only decides the debian
# revision in the version, not the compiled output.
#
# The source tree is staged under build/src first so that neither the repository
# nor the committed debian/changelog is touched by the per-distribution version
# rewrite. The stage comes from the working tree, not from HEAD, so uncommitted
# packaging changes can be tested.
#
# Results land in dist/: the binary .deb plus .changes and .buildinfo provenance,
# each package verified inside the release it is built for.
# Override the version with VERSION=..., the builder base with BASE_IMAGE=...,
# the target list with REVISIONS="1~deb12u1 1~deb13u1 1~ubuntu22.04u1".
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PLATFORM="${PLATFORM:-linux/amd64}"
BASE_IMAGE="${BASE_IMAGE:-golang:1.26-bookworm}"
VERSION="${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')}"
VERSION="${VERSION:-0.0.0}"
read -r -a REVISIONS <<<"${REVISIONS:-1~deb12u1 1~deb13u1 1~ubuntu22.04u1}"

# A revision says which release it targets, and that release is the environment
# the package gets checked in. Fail rather than verify a Debian 13 package with
# Debian 12 tools.
container_for_revision() {
	case $1 in
		*~deb12u*) echo debian:12 ;;
		*~deb13u*) echo debian:13 ;;
		*~ubuntu22.04u*) echo ubuntu:22.04 ;;
		*)
			echo "no container image mapped to revision $1" >&2
			return 1
			;;
	esac
}

STAGE=build/src
SRC="ssh-gate-$VERSION"
BUILDER_IMAGE="ssh-gate-builder:${BASE_IMAGE#*:}"

# Always run the build: docker reuses the cached layers, so an unchanged
# Dockerfile costs milliseconds and a changed one cannot be silently ignored.
docker build --platform "$PLATFORM" -t "$BUILDER_IMAGE" \
	-f packaging/Dockerfile.builder packaging

rm -rf "$STAGE"
mkdir -p "$STAGE/$SRC" dist
rm -f dist/ssh-gate_*

echo "== stage $SRC"
rsync -a --exclude .git/ --exclude .qwen/ --exclude build/ --exclude dist/ \
	--exclude '*.deb' ./ "$STAGE/$SRC/"

for rev in "${REVISIONS[@]}"; do
	echo "== build $VERSION-$rev"
	docker run --rm --platform "$PLATFORM" \
		-v "$PWD/$STAGE":/w \
		-v "$PWD/dist":/out \
		-v ssh-gate-gomod:/go/pkg/mod \
		-e DEB_VERSION="$VERSION-$rev" -e SRC="$SRC" \
		"$BUILDER_IMAGE" bash -eu -c '
			cd "/w/$SRC"
			sed -i "1s/(.*)/($DEB_VERSION)/" debian/changelog
			dpkg-buildpackage -b -us -uc
			mv ../*.deb ../*.changes ../*.buildinfo /out/'
done

echo "== verify"
for rev in "${REVISIONS[@]}"; do
	deb="dist/ssh-gate_${VERSION}-${rev}_amd64.deb"
	image=$(container_for_revision "$rev")
	echo "-- $rev in $image"
	docker run --rm --platform "$PLATFORM" \
		-v "$PWD/dist":/out:ro -e DEB="/out/$(basename "$deb")" \
		"$image" sh -c '
			dpkg-deb -I "$DEB" >/dev/null
			dpkg-deb -f "$DEB" Package Version Architecture Depends
			dpkg-deb -e "$DEB" /tmp/ctl
			printf "conffiles: "
			cat /tmp/ctl/conffiles 2>/dev/null || echo none
			dpkg-deb -c "$DEB" | awk "{print \$NF}" | grep -v "^\./$"'
done

ls -l dist/
