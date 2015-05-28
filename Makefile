MGR = dnsmgr
PLUGIN = seodns
VERSION = 0.1
LIB += seodns
seodns_SOURCES = seodns.cpp

BASE ?= /usr/local/mgr5
include $(BASE)/src/isp.mk
