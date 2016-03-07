##
 # Copyright (c) 2016 Google Inc.
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 # 1. Redistributions of source code must retain the above copyright notice,
 # this list of conditions and the following disclaimer.
 # 2. Redistributions in binary form must reproduce the above copyright notice,
 # this list of conditions and the following disclaimer in the documentation
 # and/or other materials provided with the distribution.
 # 3. Neither the name of the copyright holder nor the names of its
 # contributors may be used to endorse or promote products derived from this
 # software without specific prior written permission.
 #
 # THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 # AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 # THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 # PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 # CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 # EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 # PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 # OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 # WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 # OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 # ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ##

TOPDIR := ${shell pwd}

BOOTROM_DIR := $(HOME)/work/bootrom
BOOTROM_MCL := $(BOOTROM_DIR)/common/vendors/MIRACL

BUILDROOT := $(TOPDIR)/build
MCL_OUT := $(BUILDROOT)/MCL

#  VERBOSE==1:  Echo commands
#  VERBOSE!=1:  Do not echo commands
ifeq ($(VERBOSE),1)
export Q :=
else
export Q := @
endif

_dummy := $(shell [ -d $(OUTROOT) ] || mkdir -p $(OUTROOT))

.PHOHY: all

MIRACL_TOPDIR := $(BOOTROM_MCL)
APP_MCL_CONFIG_DIR = $(TOPDIR)/MIRACL/cfg
include $(TOPDIR)/MIRACL/Make.def

all: $(MIRACL_LIBS) ndk_build

ndk_build:
	$(Q) make -C ndk BUILDROOT=$(BUILDROOT) MIRACL_TOPDIR=$(MIRACL_TOPDIR) \
		BOOTROM_DIR=$(BOOTROM_DIR)

clean:
	$(Q) rm -rf $(BUILDROOT)
