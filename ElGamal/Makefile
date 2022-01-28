#
#         Europäisches Institut für Systemsicherheit
#   Proktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch 7: El-Gamal-Signatur
#
#-------------------------------------------------------------
#

include /home/curankar/stick/Documents/Uni/Kryptoanalyse/include/Makefile.Settings

SRC	= signsupport.c getreport.c
VHEADER = sign.h
OBJ	= $(SRC:%.c=%.o)
CFLAGS  += -g
LDFLAGS  += -lgmp

BINS	= getreport

all:	$(BINS)

getreport:	getreport.o 	signsupport.o
	$(CC) -o $@ $^ $(LDFLAGS)

signsupport.o:	signsupport.c	sign.h
getreport.o:	getreport.c	sign.h

#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS)
