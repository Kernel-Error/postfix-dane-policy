PORTNAME=	postfix-dane-policy
DISTVERSIONPREFIX=	v
DISTVERSION=	0.3.1
CATEGORIES=	mail python
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

MAINTAINER=	kernel-error@kernel-error.com
COMMENT=	DANE-aware TLS policy socketmap service for Postfix
WWW=		https://github.com/Kernel-Error/postfix-dane-policy

LICENSE=	MIT
LICENSE_FILE=	${WRKSRC}/LICENSE

BUILD_DEPENDS=	${PY_SETUPTOOLS} \
		${PYTHON_PKGNAMEPREFIX}wheel>0:devel/py-wheel@${PY_FLAVOR}
RUN_DEPENDS=	${PYTHON_PKGNAMEPREFIX}dnspython>=2.6.1:dns/py-dnspython@${PY_FLAVOR} \
		${PYTHON_PKGNAMEPREFIX}idna>=3:dns/py-idna@${PY_FLAVOR}

USES=		python
USE_GITHUB=	yes
GH_ACCOUNT=	Kernel-Error
USE_PYTHON=	autoplist pep517
USE_RC_SUBR=	postfix_dane_policy
SUB_FILES=	pkg-message

USERS=		danepolicy
GROUPS=		danepolicy
# danepolicy (801) is not registered in the ports tree yet. Until it is in
# ${PORTSDIR}/UIDs and GIDs, take the definition from files/. Drop these two
# lines and files/UIDs, files/GIDs when the port is committed.
UID_FILES=	${PORTSDIR}/UIDs ${FILESDIR}/UIDs
GID_FILES=	${PORTSDIR}/GIDs ${FILESDIR}/GIDs

NO_ARCH=	yes

PLIST_FILES=	share/man/man8/postfix-dane-policy.8.gz

post-install:
	${INSTALL_MAN} ${WRKSRC}/man/postfix-dane-policy.8 \
		${STAGEDIR}${PREFIX}/share/man/man8

do-test:
	cd ${WRKSRC} && ${SETENV} PYTHONPATH=${WRKSRC}/src \
		${PYTHON_CMD} -m unittest discover -s tests -v

.include <bsd.port.mk>
