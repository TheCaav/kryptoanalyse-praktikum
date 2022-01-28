#
#         Europäisches Institut für Systemsicherheit
#   Praktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch: Padding Oracle
#
#-------------------------------------------------------------
#
PRAKTROOT = /home/curankar/stick/Documents/Uni/Kryptoanalyse
include $(PRAKTROOT)/include/Makefile.Settings

SOURCE	= padding_client.c
HEADER	= protocol.h
OBJ	= $(SOURCE:%.c=%.o)
CFLAGS  += -g -I.
LDFLAGS  += -lgmp

BINS	= padding_client


all:	$(BINS)

padding_client:	padding_client.o
	$(CC) -o $@ $^ $(LDFLAGS)

padding_client.o:	padding_client.c	protocol.h


#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS)
