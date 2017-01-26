MGR = dnsmgr
PLUGIN = seodns
VERSION = 0.1
LIB += seodns
WRAPPER += seodns_checker
WRAPPER += seodns_add_domains

PKGNAMES = seodns-checker

RPM_PKGNAMES = $(PKGNAMES)
DEB_PKGNAMES = $(PKGNAMES)

seodns_SOURCES = seodns.cpp
seodns_checker_SOURCES = checker.cpp
seodns_checker_LDADD = -lmgr -lmgrdb

seodns_add_domains_SOURCES = add_domains.cpp
seodns_add_domains_LDADD = -lmgr -lmgrdb

BASE ?= /usr/local/mgr5
include $(BASE)/src/isp.mk
