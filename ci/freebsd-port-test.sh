#!/bin/sh
# Build, install and smoke-test the FreeBSD port from the current source tree.
# Runs as root inside a throwaway FreeBSD VM (see .github/workflows/ci.yml).
set -eu

SRC=$(pwd)
PORT=mail/py-postfix-dane-policy
VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' src/postfix_dane_policy/__init__.py)
DIST="Kernel-Error-postfix-dane-policy-v${VERSION}_GH0.tar.gz"
PY=3.12

echo "==> version ${VERSION}"

echo "DEFAULT_VERSIONS+=python=${PY} python3=${PY}" >> /etc/make.conf
pkg install -y git-tiny portlint python312 py312-dnspython py312-setuptools \
	py312-wheel py312-build py312-installer

echo "==> unit tests"
PYTHONPATH=src python${PY} -m unittest discover -s tests -v

echo "==> ports tree"
git clone --quiet --depth 1 https://git.freebsd.org/ports.git /usr/ports

echo "==> distfile from the working tree, named like the GitHub tarball"
tmp=$(mktemp -d)
mkdir "${tmp}/postfix-dane-policy-${VERSION}"
tar --exclude=.git -cf - . | tar -xf - -C "${tmp}/postfix-dane-policy-${VERSION}"
mkdir -p /usr/ports/distfiles
tar -czf "/usr/ports/distfiles/${DIST}" -C "${tmp}" "postfix-dane-policy-${VERSION}"

rm -rf "/usr/ports/${PORT}"
cp -R "${SRC}/freebsd/${PORT}" "/usr/ports/${PORT}"
cd "/usr/ports/${PORT}"
sed -i '' "s/^DISTVERSION=.*/DISTVERSION=	${VERSION}/" Makefile
make makesum

echo "==> portlint"
portlint -AC

echo "==> build"
make BATCH=yes stage
make BATCH=yes stage-qa
make BATCH=yes check-plist
make BATCH=yes package

echo "==> install package"
pkg add work/pkg/*.pkg
postfix-dane-policy --version
man -w postfix-dane-policy
sh -n /usr/local/etc/rc.d/postfix_dane_policy

echo "==> service smoke test"
sysrc postfix_dane_policy_enable=YES \
	postfix_dane_policy_args="--listen 127.0.0.1 --port 8462 --dns 1.1.1.1"
service postfix_dane_policy start
i=0
until sockstat -4l | grep -q ':8462'; do
	i=$((i + 1))
	[ "$i" -gt 20 ] && { echo "service did not start"; exit 1; }
	sleep 1
done
service postfix_dane_policy status

ask() {
	printf '%s:%s,' "$(printf '%s' "$1" | wc -c | tr -d ' ')" "$1" | nc -w 10 127.0.0.1 8462
}
r=$(ask "dane posteo.de");  echo "posteo.de -> $r";  [ "$r" = "12:OK dane-only," ]
r=$(ask "dane gmail.com");  echo "gmail.com -> $r";  [ "$r" = "9:NOTFOUND ," ]
r=$(ask "dane .gmail.com"); echo ".gmail.com -> $r"; [ "$r" = "9:NOTFOUND ," ]

service postfix_dane_policy stop
echo "==> all good"
