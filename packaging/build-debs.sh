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
# each package verified inside the release it is built for, and SHA256SUMS.txt
# holding the checksums of those packages under the names a release host serves
# (GitHub rewrites "~" to "." in asset names), so the file verifies next to the
# downloaded packages rather than in dist/.
# Override the version with VERSION=..., the builder base with BASE_IMAGE=...,
# the target list with REVISIONS="1~deb12u1 1~deb13u1 1~ubuntu22.04u1 1~ubuntu24.04u1".
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PLATFORM="${PLATFORM:-linux/amd64}"
BASE_IMAGE="${BASE_IMAGE:-golang:1.26.10-bookworm}"
VERSION="${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')}"
VERSION="${VERSION:-0.0.0}"
read -r -a REVISIONS <<<"${REVISIONS:-1~deb12u1 1~deb13u1 1~ubuntu22.04u1 1~ubuntu24.04u1}"

# A revision says which release it targets, and that release is the environment
# the package gets checked in. Fail rather than verify a Debian 13 package with
# Debian 12 tools.
container_for_revision() {
	case $1 in
		*~deb12u*) echo debian:12 ;;
		*~deb13u*) echo debian:13 ;;
		*~ubuntu22.04u*) echo ubuntu:22.04 ;;
		*~ubuntu24.04u*) echo ubuntu:24.04 ;;
		*)
			echo "no container image mapped to revision $1" >&2
			return 1
			;;
	esac
}

# coreutils and current macOS name the tool sha256sum, the BSDs ship shasum.
# Both print "<hash>  <name>", so the caller can take the first field either way.
sha256_of() {
	if command -v sha256sum >/dev/null; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

STAGE=build/src
SRC="ssh-gate-$VERSION"
BUILDER_IMAGE="ssh-gate-builder:${BASE_IMAGE#*:}"

# Always run the build: docker reuses the cached layers, so an unchanged
# Dockerfile costs milliseconds and a changed one cannot be silently ignored.
docker build --platform "$PLATFORM" -t "$BUILDER_IMAGE" \
	--build-arg BASE_IMAGE="$BASE_IMAGE" \
	-f packaging/Dockerfile.builder packaging

rm -rf "$STAGE"
mkdir -p "$STAGE/$SRC" dist
rm -f dist/ssh-gate_* dist/SHA256SUMS.txt

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
		-e OWNER="$(id -u):$(id -g)" \
		"$BUILDER_IMAGE" bash -eu -c '
			# The build runs as root; hand the stage and the results back
			# to the caller even on failure, or the next run cannot clean
			# them up.
			trap "chown -R \"\$OWNER\" /w /out" EXIT
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
			set -e
			dpkg-deb -I "$DEB" >/dev/null
			dpkg-deb -f "$DEB" Package Version Architecture Depends
			dpkg-deb -e "$DEB" /tmp/ctl
			printf "conffiles: "
			cat /tmp/ctl/conffiles 2>/dev/null || echo none
			dpkg-deb -c "$DEB" | awk "{print \$NF}" | grep -v "^\./$"
			# The maintainer scripts must leave files they do not own alone.
			# --force-depends: the check needs no network for ca-certificates.
			mkdir -p /etc/defaults
			echo keep >/etc/defaults/other
			dpkg -i --force-depends "$DEB" >/dev/null
			test -f /etc/defaults/other || { echo "postinst removed /etc/defaults/other" >&2; exit 1; }
			echo "install: ok"'
done

# One line per package: "<hash>  <name>". The names are the ones the release host
# serves, with "~" replaced by ".", because that is what the reader has next to
# the file after downloading. No comment lines: sha256sum -c reports them as
# improperly formatted.
echo "== checksums"
{
	for rev in "${REVISIONS[@]}"; do
		deb="dist/ssh-gate_${VERSION}-${rev}_amd64.deb"
		if [ ! -f "$deb" ]; then
			echo "missing $deb, refusing to write checksums" >&2
			exit 1
		fi
		printf '%s  %s\n' "$(sha256_of "$deb")" "$(basename "$deb" | tr '~' '.')"
	done
} > dist/SHA256SUMS.txt
cat dist/SHA256SUMS.txt

ls -l dist/
