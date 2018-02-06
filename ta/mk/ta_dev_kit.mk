# Get the dir of the ta-dev-kit, requires make version 3.81 or later
ta-dev-kit-dir := $(patsubst %/,%,$(abspath $(dir $(lastword $(MAKEFILE_LIST)))..))


.PHONY: all
all:

include $(ta-dev-kit-dir)/mk/conf.mk

ifneq (1, $(word $(BINARY) $(LIBNAME)))
$(error You must specify exactly one of BINARY or LIBNAME)
endif

binary := $(BINARY)
libname := $(LIBNAME)

ifneq ($O,)
out-dir := $O
else
out-dir := .
endif

ifneq ($V,1)
q := @
cmd-echo := true
cmd-echo-silent := echo
else
q :=
cmd-echo := echo
cmd-echo-silent := true
endif

ifneq ($(filter 4.%,$(MAKE_VERSION)),)  # make-4
ifneq ($(filter %s ,$(firstword x$(MAKEFLAGS))),)
cmd-echo-silent := true
endif
else                                    # make-3.8x
ifneq ($(findstring s, $(MAKEFLAGS)),)
cmd-echo-silent := true
endif
endif

cppflags$(sm)  := $($(sm)-platform-cppflags) $(CPPFLAGS_$(sm))
aflags$(sm)    := $($(sm)-platform-aflags)
cflags$(sm)    := $($(sm)-platform-cflags) $(CFLAGS_$(sm))

CFG_TEE_TA_LOG_LEVEL ?= 2
cppflags$(sm) += -DTRACE_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

ifeq ($(CFG_TEE_TA_MALLOC_DEBUG),y)
# TAs will automatically use debug versions of the malloc() functions
# in libutils (malloc() will be re-defined as mdbg_malloc() etc.).
# mdbg_check() will also be visible.
cppflags$(sm) += -DENABLE_MDBG=1
endif

cppflags$(sm) += -I. -I$(ta-dev-kit-dir)/include

libdirs += $(ta-dev-kit-dir)/lib
libnames += utils utee mpa
libdeps += $(ta-dev-kit-dir)/lib/libutils.a
libdeps += $(ta-dev-kit-dir)/lib/libmpa.a
libdeps += $(ta-dev-kit-dir)/lib/libutee.a

include $(ta-dev-kit-dir)/mk/cleandirs.mk

.PHONY: clean
clean:
	@$(cmd-echo-silent) '  CLEAN   $(out-dir)'
	${q}rm -f $(cleanfiles)
	${q}dirs="$(call cleandirs-for-rmdir)"; if [ "$$dirs" ]; then $(RMDIR) $$dirs; fi
	@$(cmd-echo-silent) '  CLEAN   $(O)'
	${q}if [ -d "$(O)" ]; then $(RMDIR) $(O); fi

subdirs = .
include  $(ta-dev-kit-dir)/mk/subdir.mk

ifneq ($(binary),)
# Build target is TA
vpath %.c $(ta-dev-kit-dir)/src
srcs += user_ta_header.c
endif

include  $(ta-dev-kit-dir)/mk/gcc.mk
include  $(ta-dev-kit-dir)/mk/compile.mk
ifneq ($(binary),)
include  $(ta-dev-kit-dir)/mk/link.mk
endif

ifneq ($(libname),)
# Build target is static library
all: $(libname).a
cleanfiles += $(libname).a

$(libname).a: $(objs)
	@echo '  AR      $@'
	$(q)rm -f $@ && $(AR$(sm)) rcs -o $@ $^
endif
