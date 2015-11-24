MGR = dnsmgr
PLUGIN = seodns
VERSION = 0.1
LIB += seodns
WRAPPER += seodns_checker

PKGNAMES = seodns-checker

RPM_PKGNAMES = $(PKGNAMES)
DEB_PKGNAMES = $(PKGNAMES)

seodns_SOURCES = seodns.cpp
seodns_checker_SOURCES = checker.cpp
seodns_checker_LDADD = -lmgr -lmgrdb

BASE ?= /usr/local/mgr5
include $(BASE)/src/isp.mk
