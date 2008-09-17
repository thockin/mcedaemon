# This file is intended to be generically useful make infrastructure.
# Anything that is really project specific should be defined outside of
# this file.

ifeq ($(strip $(TOPDIR)),)
  $(error TOPDIR is not defined)
endif
export TOPDIR

# load optional user-provided saved flags first
ifneq ($(strip $(BUILD_CONFIG)),)
  ifeq ($(BUILD_CONFIG), $(wildcard $(BUILD_CONFIG)))
    ifeq ($(DID_LOAD_BUILD_CONFIG),)
      $(info loading BUILD_CONFIG)
    endif
    include $(BUILD_CONFIG)
  endif
  export DID_LOAD_BUILD_CONFIG := 1
endif


# common build options
#
# The caller should define default values for these before including this
# file.  Use '?=' variable assignment so ENV variables can be used.
# Otherwise 'DEBUG=1 make all' would still build with debugging disabled.

export DEBUG ?= 0       # boolean: 0=no, 1=yes
export STATIC ?= 0      # option: 0=no, 1=yes, 2=partial
export PROFILE ?= 0     # boolean: 0=no, 1=yes

#FIXME: need a way to get user-defined build options, and define BUILDOPT_FOO=

# overrideable flags variables
#
# CPPFLAGS      # extra pre-processor flags
# CFLAGS        # extra C compiler flags
# CXXFLAGS      # extra C++ compiler flags
# CWARNS        # extra C compiler warnings
# CXXWARNS      # extra C++ compiler warnings
# ARCHFLAGS     # output architecture flags
# INCLUDES      # extra includes
# DEFS          # extra pre-processor definitions
# LDFLAGS       # extra linker flags
# LIBS          # extra linker libs, linked statically for non-zero STATIC=
# LIBS_DYN      # extra linker libs, linked dynamically unless STATIC=1
# TRACE         # a list of trace names (e.g.: TRACE="FOO BAR" turns into
#               #   -DTRACE_FOO -DTRACE_BAR)


# per-target flags variables
#
# $@_CPPFLAGS   # extra pre-processor flags
# $@_CFLAGS     # extra C compiler flags
# $@_CXXFLAGS   # extra C++ compiler flags
# $@_CWARNS     # extra C compiler warnings
# $@_CXXWARNS   # extra C++ compiler warnings
# $@_INCLUDES   # extra includes
# $@_DEFS       # extra pre-processor definitions
# $@_LDFLAGS    # extra linker flags
# $@_LIBS       # extra linker libs, linked statically for non-zero STATIC=
# $@_LIBS_DYN   # extra linker libs, linked dynamically unless STATIC=1


# build tools

CPP = $(CROSS_COMPILE)cpp
CC  = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++


# build flags

PRJ_CPPFLAGS   = $($@_CPPFLAGS)
PRJ_CFLAGS     = $(ARCHFLAGS) $($@_CFLAGS)
PRJ_CXXFLAGS   = $(PRJ_CFLAGS) $($@_CXXFLAGS)
PRJ_LDFLAGS    = $(ARCHFLAGS) $($@_LDFLAGS)
PRJ_CWARNS     = -W -Wall -Wextra -Werror $(CWARNS) $($@_CWARNS)
PRJ_CXXWARNS   = $(PRJ_CWARNS) -Woverloaded-virtual $(CXXWARNS) $($@_CXXWARNS)
PRJ_DEFS       = -DPRJ_VERSION="\"$(PRJ_VERSION)\"" $(DEFS) $($@_DEFS)
PRJ_INCLUDES   = -I$(TOPDIR) $(INCLUDES) $($@_INCLUDES)
PRJ_LDLIBS     = $(LIBS) $($@_LDLIBS)
PRJ_LDLIBS_DYN = $(LIBS_DYN) $($@_LDLIBS_DYN)

ifeq ($(strip $(STATIC)),1)
PRJ_STATIC  = -static
PRJ_DYNAMIC =
endif
ifeq ($(strip $(STATIC)),2)
PRJ_STATIC  = -Wl,-Bstatic
PRJ_DYNAMIC = -Wl,-Bdynamic
endif

ifeq ($(strip $(PROFILE)),1)
ifeq ($(strip $(DEBUG)),1)
$(warning WARNING: PROFILE and DEBUG are both enabled)
endif
PRJ_CFLAGS  += -pg
PRJ_LDFLAGS += -pg
PRJ_LDLIBS  += -lgcov
endif

# debug options should go last
ifeq ($(strip $(DEBUG)),1)
PRJ_TRACE    = $(foreach trace, $(TRACE), -DTRACE_$(trace)=1)
PRJ_CDEBUG   = -O0 -ggdb -DDEBUG -UNDEBUG $(PRJ_TRACE)
PRJ_CXXDEBUG = $(PRJ_CDEBUG) -fno-default-inline
else
PRJ_CDEBUG   = -O2 -DNDEBUG
endif

CPPFLAGS += $(PRJ_DEFS) $(PRJ_INCLUDES)
CFLAGS   += $(PRJ_CFLAGS) $(PRJ_CWARNS) $(PRJ_CDEBUG)
CXXFLAGS += $(PRJ_CXXFLAGS) $(PRJ_CXXWARNS) $(PRJ_CXXDEBUG)
LDFLAGS  += $(PRJ_LDFLAGS)
LDLIBS   += $(PRJ_STATIC) $(PRJ_LDLIBS) $(PRJ_DYNAMIC) $(PRJ_LDLIBS_DYN)


# common rules

# this is the default rule, which the calling Makefile should define
.PHONY: all
all: make_flags

.PHONY: make_flags
make_flags:
	@\
	NEW=$$($$(which echo) -e \
	       "CPP='$$(which $(CPP))'\n" \
	       "CC='$$(which $(CC))'\n" \
	       "CXX='$$(which $(CXX))'\n" \
	       "CROSS_COMPILE='$(CROSS_COMPILE)'\n" \
	       "CFLAGS='$(CFLAGS)'\n" \
	       "CXXFLAGS='$(CXXFLAGS)'\n" \
	       "CPPFLAGS='$(CPPFLAGS)'\n" \
	       "LDFLAGS='$(LDFLAGS)'\n" \
	       "LDLIBS='$(LDLIBS)'\n"); \
	OLD=$$(cat .make_flags 2>/dev/null); \
	if [ "$$NEW" != "$$OLD" ]; then \
		$(MAKE) clean; \
		echo "$$NEW" > .make_flags; \
	fi

.PHONY: clean_make_flags
clean_make_flags:
	@$(RM) .make_flags

.PHONY: clean
clean: clean_make_flags

.PHONY: clean_depends
clean_depends:
	@$(RM) .depend

.PHONY: distclean
distclean: clean clean_depends

.PHONY: dep depend
dep depend:
	@$(RM) .depend
	@$(MAKE) .depend

.depend:
	@for f in $^; do \
		OBJ=$$(echo $$f | sed 's/\.cp*$$/.o/'); \
		$(CPP) $(CPPFLAGS) -MM $$f -MT $$OBJ; \
	done > $@.tmp; \
	diff -w -B -q $@ $@.tmp >/dev/null 2>&1; \
	if [ $$? != 0 ]; then \
		mv -f $@.tmp $@; \
	else \
		$(RM) $@.tmp; \
	fi

# a generic empty target to force some rules
.PHONY: FORCE
FORCE:

.PHONY: run_tests
run_tests:
	@for f in $(RUN_TESTS); do \
		echo -n "TEST $$f: "; \
		./$$f > $$f.err 2>&1; \
		if [ "$$?" -eq "0" ]; then \
			echo PASS; \
		else \
			echo FAIL; \
		fi; \
		cat $$f.err | sed 's/^/  /'; \
		$(RM) -f $$f.err; \
	done 2>/dev/null

# NOTE: 'sinclude' is "silent-include".  This suppresses a warning if
# .depend does not exist.  Since Makefile includes this file, and this
# file includes .depend, .depend is itself "a makefile" and Makefile is
# dependent on it.  Any makefile for which there is a rule (as above for
# .depend) will be evaluated before anything else.  If the rule executes
# and the makefile is updated, make will reload the original Makefile and
# start over.
#
# This means that the .depend rule will always be checked first.  If
# .depend gets rebuilt, then the dependencies we have already sincluded
# must have been stale.  Make starts over, the old dependencies are
# tossed, and the new dependencies are sincluded.
#
# So why use 'sinclude' instead of 'include'?  We want to ALWAYS make
# Makefile depend on .depend, even if .depend doesn't exist yet.  But we
# don't want that pesky warning.
sinclude .depend
