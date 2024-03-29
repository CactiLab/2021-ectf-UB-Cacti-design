#  2021 Collegiate eCTF
#  SCEWL Bus Controller Makefile
#  Ben Janis
#
#  (c) 2021 Cacti Team
#


# define the part type and base directory - must be defined for makedefs to work
PART=LM3S6965
ROOT=.

# include the common make definitions
include lm3s/makedefs

# add additional directories to search for source files to VPATH
VPATH=lm3s

# add additional directories to search for header files to IPATH
IPATH=${ROOT}
IPATH+=${ROOT}/CMSIS/Include
IPATH+=${VPATH}

# add flags to pass to the compiler
CFLAGS+=-w
CFLAGS+=-DSCEWL_ID=${SCEWL_ID}

# this rule must come first in `all`
all: ${COMPILER}

# for each source file that needs to be compiled besides
# the file that defines `main`, add the next two lines 
LDFLAGS+=${COMPILER}/interface.o
all: ${COMPILER}/interface.o

################ start crypto example ################
# example AES rules to build in tiny-AES-c: https://github.com/kokke/tiny-AES-c
# make sure submodule has been pulled (run `git submodule update --init`)
# uncomment next line to activate
# EXAMPLE_AES=foo
ifdef EXAMPLE_AES
# path to crypto library
CRYPTOPATH=./tiny-AES-c

# add path to crypto source files to source path
VPATH+=${CRYPTOPATH}

# add crypto library to includes path
IPATH+=${CRYPTOPATH}

# add crypto object file to includes path
LDFLAGS+=${COMPILER}/aes.o

# add compiler flag to enable example AES code 
CFLAGS+=-DEXAMPLE_AES

# add rule to build crypto library
all: ${COMPILER}/aes.o
endif
################ end crypto example ################

################ add aes256-gcm lib ################
# uncomment next line to activate
AES_GCM=foo
ifdef AES_GCM
# path to crypto library
CRYPTOPATH=./aes256-gcm

# add path to crypto source files to source path
VPATH+=${CRYPTOPATH}

# add crypto library to includes path
IPATH+=${CRYPTOPATH}

# add crypto object file to includes path
LDFLAGS+=${COMPILER}/gcm.o aes.o aes-gcm.o

# add compiler flag to enable AES_GCM 
CFLAGS+=-DAES_GCM

# add rule to build crypto library
all: ${COMPILER}/gcm.o aes.o aes-gcm.o
endif

################ add RSA ################
RSA=foo
ifdef RSA
# path to auth library
RSAPATH=./rsa

# add path to auth source files to source path
VPATH+=${RSAPATH}

# add auth library to includes path
IPATH+=${RSAPATH}

# add auth object file to includes path
LDFLAGS+=${COMPILER}/bn.o keys.o rsa.o

# add rule to build auth library
all: ${COMPILER}/bn.o keys.o rsa.o
endif

# ################ add sha1 ################

# path to auth library
MD5PATH=./auth

# add path to auth source files to source path
VPATH+=${MD5PATH}

# add auth library to includes path
IPATH+=${MD5PATH}

# add auth object file to includes path
LDFLAGS+=${COMPILER}/md5.o

# add rule to build auth library
all: ${COMPILER}/md5.o

###########################################
# this must be the last build rule of `all`
all: ${COMPILER}/controller.axf

# clean all build products
clean:
	@rm -rf ${COMPILER} ${wildcard *~}

# create the output directory
${COMPILER}:
	@mkdir ${COMPILER}

# check that SCEWL_ID is defined
check_defined = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined,$1)))
__check_defined = \
    $(if $(value $1),, \
      $(error Undefined $1))
arg_check:
	$(call check_defined, SCEWL_ID)

${COMPILER}/controller.axf: arg_check
${COMPILER}/controller.axf: ${COMPILER}/controller.o
${COMPILER}/controller.axf: ${COMPILER}/startup_${COMPILER}.o
${COMPILER}/controller.axf: ${COMPILER}/system_lm3s.o
ifeq (${COMPILER}, gcc)
${COMPILER}/controller.axf: lm3s/controller.ld
endif
SCATTERgcc_controller=lm3s/controller.ld
ifeq (${COMPILER}, sourcerygxx)
${COMPILER}/controller.axf: controller_sourcerygxx.ld
endif
SCATTERsourcerygxx_controller=lm3s6965-rom.ld -T controller_sourcerygxx.ld
ENTRY_controller=Reset_Handler

#
# Include the automatically generated dependency files.
#
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${COMPILER}/*.d} __dummy__
endif
