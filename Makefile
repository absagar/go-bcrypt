#
# _copyright__
#

include $(GOROOT)/src/Make.inc

TARG = bitbucket.org/zoowar/bcrypt

CGOFILES = \
        bcrypt.go \

CGO_OFILES = \
	bcrypt.o \
	blowfish.o \

include $(GOROOT)/src/Make.pkg

%: install %.go
	$(GC) $*.go
	$(LD) -o $@ $*.$O
