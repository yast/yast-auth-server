#
# Makefile.am for SlapdConfig agent
#
AM_CPPFLAGS= -I$(top_srcdir)/lib  -I/usr/include/YaST2
AM_CXXFLAGS = -DY2LOG=\"agent-slapdconfig\" -Wall
plugin_LTLIBRARIES = libpy2ag_slapdconfig.la
noinst_LTLIBRARIES = liby2ag_slapdconfig.la

liby2ag_slapdconfig_la_SOURCES =				\
	SlapdConfigAgent.cc					\
	SlapdConfigAgent.h
liby2ag_slapdconfig_la_LDFLAGS = -version-info 2:0
liby2ag_slapdconfig_la_LIBADD = ../lib/libslapdconfig.la @AGENT_LIBADD@ -L$(libdir) 

libpy2ag_slapdconfig_la_SOURCES =				\
	$(liby2ag_slapdconfig_la_SOURCES)			\
	Y2CCSlapdConfigAgent.cc

libpy2ag_slapdconfig_la_LDFLAGS = -version-info 2:0
libpy2ag_slapdconfig_la_LIBADD = ../lib/libslapdconfig.la @AGENT_LIBADD@ -L$(libdir) 

INCLUDES = -I$(includedir)


# ----------- temporary handle also perl/ycp files:

include $(top_srcdir)/Makefile.am.common

