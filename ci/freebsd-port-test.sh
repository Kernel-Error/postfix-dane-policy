#!/bin/sh
# Build, install and smoke-test the FreeBSD port from the current source tree.
# Runs as root inside a throwaway FreeBSD VM (see .github/workflows/ci.yml).
set -eu

SRC=$(pwd)
PORT=mail/py-postfix-dane-policy
VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' src/postfix_dane_policy/__init__.py)
DIST="Kernel-Error-postfix-dane-policy-v${VERSION}_GH0.tar.gz"
PY=3.12
SVC_UID=801
SOCK=/var/run/postfix_dane_policy/policy.sock

echo "==> version ${VERSION}"

printf "DEFAULT_VERSIONS+=python=${PY} python3=${PY}\nDEVELOPER=yes\n" >> /etc/make.conf
pkg install -y git-tiny portlint python312 py312-dnspython py312-idna py312-setuptools \
	py312-wheel py312-build py312-installer

echo "==> unit tests"
PYTHONPATH=src python${PY} -m unittest discover -s tests -v

echo "==> ports tree"
git clone --quiet --depth 1 https://git.freebsd.org/ports.git /usr/ports

echo "==> UID/GID ${SVC_UID} must still be free in the ports tree"
# The port ships its own account definition (files/UIDs, files/GIDs) until
# danepolicy is registered upstream; the tree is NOT patched here, so this
# tests exactly what a user following the README does.
if grep -q '^danepolicy:' /usr/ports/UIDs; then
	echo "danepolicy is registered upstream now, drop UID_FILES/GID_FILES from the port"
elif cut -d: -f3 /usr/ports/UIDs | grep -qx "${SVC_UID}" || \
    cut -d: -f3 /usr/ports/GIDs | grep -qx "${SVC_UID}"; then
	echo "UID/GID ${SVC_UID} is taken in the ports tree, pick another one"
	exit 1
fi

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
make clean
# portlint -C (committer mode) expects the port to be tracked by git
git -C /usr/ports add "${PORT}"

echo "==> portlint"
portlint -AC

echo "==> build"
make BATCH=yes stage
make BATCH=yes stage-qa
make BATCH=yes check-plist
make BATCH=yes package

echo "==> install package"
pkg add "$(make -V WRKDIR)"/pkg/*.pkg
postfix-dane-policy --version
man -w postfix-dane-policy
sh -n /usr/local/etc/rc.d/postfix_dane_policy
id danepolicy

echo "==> service smoke test (unix socket, dedicated user)"
pw groupshow postfix >/dev/null 2>&1 || pw groupadd postfix -g 125
sysrc postfix_dane_policy_enable=YES \
	postfix_dane_policy_args="--socket ${SOCK} --dns 1.1.1.1"
service postfix_dane_policy start
i=0
until [ -S "${SOCK}" ]; do
	i=$((i + 1))
	[ "$i" -gt 20 ] && { echo "service did not start"; exit 1; }
	sleep 1
done
service postfix_dane_policy status

echo "==> ownership and permissions"
dirperm=$(stat -f '%Su:%Sg %Lp' /var/run/postfix_dane_policy)
pidowner=$(stat -f '%Su' /var/run/postfix_dane_policy.pid)
svcuser=$(ps -axo user,command | awk '/[p]ython.*postfix-dane-policy/ {print $1; exit}')
echo "dir=${dirperm} pidfile=${pidowner} service=${svcuser}"
[ "${dirperm}" = "danepolicy:postfix 750" ]
[ "${pidowner}" = "root" ]
[ "${svcuser}" = "danepolicy" ]

ask() {
	printf '%s:%s,' "$(printf '%s' "$1" | wc -c | tr -d ' ')" "$1" | nc -U -w 10 "${SOCK}"
}
r=$(ask "dane posteo.de");  echo "posteo.de -> $r";  [ "$r" = "12:OK dane-only," ]
r=$(ask "dane gmail.com");  echo "gmail.com -> $r";  [ "$r" = "9:NOTFOUND ," ]
r=$(ask "dane .gmail.com"); echo ".gmail.com -> $r"; [ "$r" = "9:NOTFOUND ," ]

echo "==> socket access: postfix group yes, others no"
pw useradd pdptest -g postfix -d /nonexistent -s /bin/sh
connect_as() {
	su -m "$1" -c "python${PY} -c 'import socket, sys; s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); print(\"connected\")' ${SOCK}" 2>&1 || true
}
out=$(connect_as pdptest); echo "pdptest (group postfix): $out"
[ "$out" = "connected" ]
out=$(connect_as nobody);  echo "nobody: $out"
echo "$out" | grep -q PermissionError

service postfix_dane_policy stop
[ ! -S "${SOCK}" ] || { echo "socket not removed on stop"; exit 1; }

# The port skeleton lives inside the tarball, so distinfo can only be updated
# in a commit after the release tag. Once it names the current version it has
# to match the real GitHub tarball.
if grep -q "${DIST}" "${SRC}/freebsd/${PORT}/distinfo"; then
	echo "==> verify committed distinfo against the real GitHub tarball"
	rm -f "/usr/ports/distfiles/${DIST}"
	rm -rf "/usr/ports/${PORT}"
	cp -R "${SRC}/freebsd/${PORT}" "/usr/ports/${PORT}"
	cd "/usr/ports/${PORT}"
	make fetch checksum
else
	echo "==> distinfo not yet updated for ${VERSION} (expected before the release commit), skipping"
fi

echo "==> all good"
