# Copyright (c) 2010 Freescale Semiconductor, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#	notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#	notice, this list of conditions and the following disclaimer in the
#	documentation and/or other materials provided with the distribution.
#     * Neither the name of Freescale Semiconductor nor the
#	names of its contributors may be used to endorse or promote products
#	derived from this software without specific prior written permission.
#
#
# ALTERNATIVELY, this software may be distributed under the terms of the
# GNU General Public License ("GPL") as published by the Free Software
# Foundation, either version 2 of that License or (at your option) any
# later version.
#
# THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# All "Makefile.sub"s found beneath these directories are procssed;
DIRS := apps drivers

# ----=[ Arch specific definitions ]=----
ifneq (distclean,$(MAKECMDGOALS))
 ifeq (powerpc,$(ARCH))
   CROSS_COMPILE	?= powerpc-linux-gnu-
   $(ARCH)_SPEC_DEFINE	:= _FILE_OFFSET_BITS=64
   $(ARCH)_SPEC_INC_PATH:=
   $(ARCH)_SPEC_LIB_PATH:=
   $(ARCH)_SPEC_CFLAGS	:= -mcpu=e500mc -D_GCCPORT_ -D__POWERPC__ -D__PPC_EABI__ -mmultiple -mno-altivec -pthread -O2 -Wall -Wshadow
   $(ARCH)_SPEC_LDFLAGS	:=
 else
   $(error "ARCH not defined.")
 endif
endif

# ----[ Tools ]----
MAKE		?= make
INSTALL		?= install
CC		:= $(CROSS_COMPILE)gcc
LD		:= $(CROSS_COMPILE)ld
AR		:= $(CROSS_COMPILE)ar

# ----=[ Directories and flags ]=----
TOP_LEVEL	:= $(shell pwd)
DESTDIR		?= $(TOP_LEVEL)/test_install
PREFIX		?= usr
INSTALL_BIN	?= $(PREFIX)/bin
INSTALL_SBIN	?= $(PREFIX)/sbin
INSTALL_LIB	?= $(PREFIX)/lib
INSTALL_OTHER	?= $(PREFIX)/etc
OBJ_DIR		:= objs_$(ARCH)
BIN_DIR		:= $(TOP_LEVEL)/bin_$(ARCH)
LIB_DIR		:= $(TOP_LEVEL)/lib_$(ARCH)
CFLAGS		:= $(EXTRA_CFLAGS) $($(ARCH)_SPEC_CFLAGS)
CFLAGS		+= $(addprefix -D,$($(ARCH)_SPEC_DEFINE) $(EXTRA_DEFINE))
CFLAGS		+= -I$(TOP_LEVEL)/include $(addprefix -I,$($(ARCH)_SPEC_INC_PATH))
LDFLAGS		:= $(EXTRA_LDFLAGS) $($(ARCH)_SPEC_LDFLAGS)
LDFLAGS		+= $(addprefix -L,$(LIB_DIR)) $(addprefix -L,$($(ARCH)_SPEC_LIB_PATH))
ARFLAGS		:= rcs
INSTALL_FLAGS	?= -D
INSTALL_BIN_FLAGS ?= --mode=755
INSTALL_SBIN_FLAGS ?= --mode=700
INSTALL_LIB_FLAGS ?= --mode=644
INSTALL_OTHER_FLAGS ?= --mode=644

#----=[ Control verbosity ]=----
ifndef V
 Q := @
endif

# ----=[ Default target ]=----
all: $(BIN_DIR) $(LIB_DIR) build

#----=[ Helpers for "make debug" ]=----
print_obj = echo "	     (compile) $(2) -> $(3)$(1)";
define print_debug_lib
 echo "	  $(1): $(addsuffix .o,$(basename $($(1)_SOURCES)))";
 echo "	     (path) $($(1)_dir)/";
$(foreach s,$($(1)_SOURCES), $(call print_obj,$(basename $(s)).o,$(s),$($(1)_pref)))
 echo;
endef
define print_debug_bin
 echo "	  $(1): $(addsuffix .o,$(basename $($(1)_SOURCES)))";
 echo "	     (path) $($(1)_dir)/";
$(foreach s,$($(1)_SOURCES), $(call print_obj,$(basename $(s)).o,$(s),$($(1)_pref)))
 echo "	     (link with) $($(1)_LDADD)"
 echo;
endef
define print_debug_mk
 echo "	  $(1)";
endef
define print_debug_install
 $(eval DESTDIR?=<DESTDIR>)
 echo "	  $(1) NAME:$($(1)_install_name)"
 echo "	     FROM:  $($(1)_install_from)"
 echo "	     DEST:  $(DESTDIR)/$($(1)_install_to)"
 echo "	     FLAGS: $($(1)_install_flags)"
 echo
endef

# ----=[ Processing Makefile.sub input ]=----
define process_install
do_install_$(1):$($(1)_install_from)/$($(1)_install_name)
	$$(Q)echo " [INSTALL] $(1)"
	$$(Q)$(INSTALL) $(INSTALL_FLAGS) $($(1)_install_flags) $($(1)_install_from)/$($(1)_install_name) $(DESTDIR)/$($(1)_install_to)/$($(1)_install_name)
do_uninstall_$(1):
	$$(Q)echo " [UNINSTALL] $(1)"
	$$(Q)rm -f $(DESTDIR)/$($(1)_install_to)/$($(1)_install_name)
endef

define pre_process_target
  $(eval myinstall := $(strip $($(1)_install)))
  $(eval myiflags := $(strip $($(1)_install_flags)))
  $(eval $(1)_dir := $(2))
  $(eval $(1)_mk_cflags := $(3))
  $(eval myprefix = $($(1)_dir)/$(OBJ_DIR)/$(1)_)
  $(eval $(1)_pref := $(myprefix))
  $(eval $(1)_objs := $(foreach s,$(filter %.c,$($(1)_SOURCES)),$(myprefix)$(basename $(s)).o))
  ifneq (none,$(myinstall))
    ifeq (,$(myinstall))
      $(1)_install_to := $(5)
    else
      $(1)_install_to := $(myinstall)
    endif
    ifeq (,$(strip $(6)))
      $(1)_install_from := $(strip $(2))
    else
      $(1)_install_from := $(strip $(6))
    endif
    ifeq (,$(myiflags))
      $(1)_install_flags := $(7)
    else
      $(1)_install_flags := $(myiflags)
    endif
    $(eval $(1)_install_name := $(4))
    $(eval TO_INSTALL += $(1))
  endif
endef

define process_obj
$($(1)_pref)$(3).o:$($(1)_dir)/$(2)
	$$(Q)mkdir -p $$(dir $$@)
	$$(Q)echo " [CC] $$(shell printf '%- 16s (%s:%s)' $(2) $($(1)_type) $(1))"
	$$(Q)touch  $$(patsubst %.o,%.d,$$@)
	$$(Q)$(CC) -MMD -MP -MF$$(patsubst %.o,%.d,$$@) $(CFLAGS) $($(1)_CFLAGS) $($(1)_mk_cflags) -I$$(dir $$<)include -c $$< -o $$@
endef

define process_bin
$(eval $(call pre_process_target,$(1),$(2),$(3),$(1),$(INSTALL_BIN),$(BIN_DIR),$(INSTALL_BIN_FLAGS)))
$(eval $(1)_type := bin)
$(foreach x,$(filter %.c,$($(1)_SOURCES)),$(eval $(call process_obj,$(1),$(x),$(basename $(x)))))
$(BIN_DIR)/$(1):$($(1)_objs) $(addprefix $(LIB_DIR)/lib,$(addsuffix .a,$($(1)_LDADD)))
	$$(Q)echo " [LD] $$(notdir $$@)";
	$$(Q)$(CC) $($(1)_objs) $(LDFLAGS) $($(1)_LDFLAGS) $(addprefix -l,$($(1)_priv_LDADD)) $(addprefix -l,$($(1)_LDADD)) $(addprefix -l,$($(1)_sys_LDADD)) -lc -o $$@
endef

define process_lib
$(eval $(call pre_process_target,$(1),$(2),$(3),lib$(1).a,$(INSTALL_LIB),$(LIB_DIR),$(INSTALL_LIB_FLAGS)))
$(eval $(1)_type := lib)
$(foreach x,$(filter %.c,$($(1)_SOURCES)),$(eval $(call process_obj,$(1),$(x),$(basename $(x)))))
$(LIB_DIR)/lib$(1).a:$($(1)_objs)
	$(Q)echo " [AR] $$(notdir $$@)"
	$(Q)$(AR) $(ARFLAGS) $$@ $($(1)_objs)
endef

define process_makefile
  $(eval include $(1))
  $(eval thisdir := $(2:%/=%))
  $(eval cflags := $(my_CFLAGS))
  $(foreach B,$(bin_PROGRAMS),$(eval $(call process_bin,$(B),$(thisdir),$(cflags))))
  $(foreach L,$(lib_LIBRARIES),$(eval $(call process_lib,$(L),$(thisdir),$(cflags))))
  $(foreach x,$(my_DATA),$(eval $(call pre_process_target,$(x),$(thisdir),\
  	$(cflags),$(x),$(INSTALL_OTHER),,$(INSTALL_OTHER_FLAGS))))
  BINS += $(bin_PROGRAMS)
  LIBS += $(lib_LIBRARIES)
  bin_PROGRAMS :=
  lib_LIBRARIES :=
  my_DATA :=
  my_CFLAGS :=
endef

ALL_MAKEFILES := $(foreach d,$(DIRS),$(shell find $(d) -name Makefile.sub))
$(foreach M,$(ALL_MAKEFILES), $(eval $(call process_makefile,$(M),$(dir $(M)))))
$(foreach x,$(TO_INSTALL),$(eval $(call process_install,$(x))))

# ----=[ Other make targets ]=----
$(BIN_DIR):
	$(Q)mkdir -p $(BIN_DIR)

$(LIB_DIR):
	$(Q)mkdir -p $(LIB_DIR)

build:$(foreach lib,$(LIBS),$(LIB_DIR)/lib$(lib).a) $(foreach bin,$(BINS),$(BIN_DIR)/$(bin))

install: $(addprefix do_install_,$(TO_INSTALL))

uninstall: $(addprefix do_uninstall_,$(TO_INSTALL))

debug:
	@echo "LIBS"
	@echo "	  $(LIBS)"
	@echo
	@echo "LIB_DEPS"
	@$(foreach lib,$(LIBS),$(call print_debug_lib,$(lib)))
	@echo
	@echo "BINS"
	@echo "	  $(BINS)"
	@echo
	@echo "BIN_DEPS"
	@$(foreach bin,$(BINS),$(call print_debug_bin,$(bin)))
	@echo
	@echo "ALL_MAKEFILES"
	@$(foreach mk,$(ALL_MAKEFILES),$(call print_debug_mk,$(mk)))
	@echo
	@echo "TO BE INSTALLED"
	@$(foreach i,$(TO_INSTALL),$(call print_debug_install,$(i)))

clean:
	$(Q)echo "---- clean ----"
	$(Q)rm -f $(foreach a,$(BINS) $(LIBS),$($(a)_objs))

distclean:
	$(Q)echo "---- distclean ----"
	$(Q)rm -fr $(BIN_DIR)
	$(Q)rm -fr $(LIB_DIR)
	$(Q)rm -fr $(TOP_LEVEL)/test_install
	$(Q)find -name $(OBJ_DIR) |xargs rm -fr
	$(Q)find -name \*.o |xargs rm -f
	$(Q)find -name \*.d |xargs rm -f

# ----=[ Include auto-generated dependencies ]=---- 
-include $(foreach lib,$(LIBS),$(patsubst %.o,%.d,$($(lib)_objs)))
-include $(foreach bin,$(BINS),$(patsubst %.o,%.d,$($(bin)_objs)))
