#
#         Europäisches Institut für Systemsicherheit
#   Proktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch: BREACH
#
#-------------------------------------------------------------
#

include /home/curankar/stick/Documents/Uni/Kryptoanalyse/include/Makefile.Settings

SOURCE	= attack.c
HEADER	= breach.h
OBJ	= $(SOURCE:%.c=%.o)
CFLAGS  += -g

BINS	= attack


all:	$(BINS)

attack:	attack.o
	$(CC) -o $@ $^ $(LDFLAGS)

attack.o:	attack.c	breach.h


#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS)
