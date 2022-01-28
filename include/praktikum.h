/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Praktikum-Support-Library                                 *
**                                                           *
**************************************************************
**
** praktikum.h: Prototypes der Hilfsfunktionen, nützliche Makros
**/

#ifndef _PRAKTIKUM_H
#  define _PRAKTIKUM_H

/******************************************************************************/
/*                      System-Header-Dateien einlesen                        */
/******************************************************************************/
#  ifndef FILE
#    include <stdio.h>
#  endif
#  ifndef __stdlib_h
#    include <stdlib.h>
#  endif
#  ifndef __string_h
#    include <string.h>
#  endif
#  ifndef _errno_h
#    include <errno.h>
#  endif
#  ifndef __gmplib_h
#    include <gmp.h>
#  endif
#include <inttypes.h>
/******************************************************************************/
/*                      Einige globalen Typen und Makros                      */
/******************************************************************************/
#define STRINGLEN        256      /* Länge von 'handelsüblichen' Strings */
#define BYTELEN       	  256      /* Anzahl an mit einem Byte darstellbaren Zahlen */
#define MPZLEN     	  129      /* Anzahl an Bytes, welche in einer 2048-Bit-Langzahl reinpassen */

typedef char String[STRINGLEN];

#define linux
#define LOWBYTEFIRST
#define ANSI
#define ANSIINCLUDE

#define TABSIZE(t) (sizeof(t)/sizeof(*t)) /* Gibt Anzahl der Einträge einer Tabelle zurück */

/* read in int form /dev/urandom */
extern int cs_rand(void);
extern void cs_srand(void);
extern uint8_t cs_rand_byte(void);
extern void cs_rand_buf(unsigned char *buf, size_t len);
/* RandomNumber() erzeugt eine 32-Bit breite Zufallszahl */
extern uint32_t RandomNumber(void);


/******************************************************************************/
/*                         String-Funktionen                                  */
/******************************************************************************/

/* string_to_lower(s): Konvertiert S nach Kleinschrift */
extern void string_to_lower(char *s);

/* string_to_upper(s): Konvertiert S nach Großschrift */
extern void string_to_upper(char *s);

/* strip_crlf(s): Entfernt vom Ende des Strings CR und LF */
extern void strip_crlf(char *s);

/* conectstrings(s1,s2,s3,...,NULL) gibt einen Zeiger auf die
 *    zusammengefaßten Strings S1 usw. zurück. */
extern char *concatstrings(const char *s1,...);


/******************************************************************************/
/*                       Ein- und Ausgabe Funktionen                          */
/******************************************************************************/

/* readstring(prompt,buffer,buffersize) : Liest einen String der maximalen
 *    Länge SIZE-2 nach BUFFER von der Standardeingabe ein. Zuvor wird
 *    PROMPT ausgegeben. Das abschließende LF wird nicht mit zurückgegeben.
 */
extern void readstring(const char *prompt, char *buffer, int size);

/* int readint(prompt) : Gibt (optional) prompt aus und liest von der
 *    Standardeingabe ein Integer (-2^31 .. 2^31 - 1) ein und gibt dieses
 *    als Ergebnis zurück. Handelt es sich bei der Eingabe nicht um eine
 *    korrekte Zahl, so gibt readint() "????" aus und wiederholt die Eingabe.
 *    Die Zahl kann dezimal, Hexadezimal (mit führendem `0x') oder oktal (mit
 *    führender `0') angegeben werden.
 */
extern int readint(const char *prompt);

/* double readdouble(prompt) : Gibt (optional) prompt aus und liest eine
 *    (dezimale!) Fließkommazahl von der Standardeingabe ein und gibt sie als Ergebnis
 *    zurück. Handelt es sich bei der Eingabe nicht um eine
 *    korrekte Zahl, so gibt readint() "????" aus und wiederholt die Eingabe.
 */
extern double readdouble(const char *prompt);

/* char readchar(const char *prompt): Gibt (optional) prompt aus und liest
 *    ein einzelnes Zeichen von der Standardeingabe. Im Gegensatz zu den
 *    vorhergehenden Routinen benötigt readchar kein die Eingabe abschließendes
 *    Enter!
 */
extern char readchar(const char *prompt);

/* Kompatibilität zur Vorgänger-Version der Bibliothek */
#define readline(prompt,buffer,size) readstring(prompt,buffer,size)

/*
 * printstring_escaped(s,len) : Gibt aus S LEN viele Zeichen aus und expandiert dabei
 *   Steuerzeichen, sodaß diese sichtbar werden.
 */
void printstring_escaped(FILE *out, const char *s,int len);
void printstring_escaped_unsigned(FILE *out, const unsigned char *s,int len);

/******************************************************************************/
/*                 Datentypen und Funktionen für den DES                      */
/******************************************************************************/

#define DES_DATA_WIDTH  8  /* Breite des DES in Bytes     */

typedef uint8_t DES_key[DES_DATA_WIDTH];  /* User-key                    */
typedef uint8_t DES_data[DES_DATA_WIDTH]; /* Ein- und Ausgabedaten       */
typedef uint32_t DES_ikey[32]; /* Schlssel nach Aufbereitung */

/* DES_GenKeys erzeugt aus dem 8 Byte langen Schlüssen KEY den internen Schlüssel-
 * satz IKEY, der zum Vr- (DECODEFLG==0) bzw. entschlüsseln (DECODEFLG!=0)
 * in DES_Cipher angegeben werden muß. */
extern void   DES_GenKeys( const DES_key key, int decodeflg, DES_ikey ikey );

/* DES_Cipher ver- bzw. entschlüsselt 8 Bytes von INP nach OUT (Überlappung ist
 * zulässig). IKEY ist der Schlüssel in der internen Form, wie er mit DES_GenKeys
 * erzeugt wurde. */
extern void   DES_Cipher( const DES_ikey key, const DES_data inp, DES_data out );


/* DES_CFB_Enc/DES_CFB_Dec ver- und entschlüsseln im CFB-Modus. IKEY
 * für beide Funktionen zum Verschlüsseln generiert worden sein. Der
 " Schiebefaktor" beträgt 1, d.h. LEN kann beliebig sein. */
extern void DES_CFB_Enc(const DES_ikey ikey,DES_data iv,const uint8_t *src,int len,uint8_t *dst);
extern void DES_CFB_Dec(const DES_ikey ikey,DES_data iv,const uint8_t *src,int len,uint8_t *dst);

/******************************************************************************/
/*                           Diverses                                         */
/******************************************************************************/

/* CurrentTime()ibt die aktuelle Uhrzeit in 1/1000 Sekunden seit
 * dem 1. Januar 1980 zurück. */
extern uint32_t GetCurrentTime(void);

/* Ausgabe von Datum und Uhrzeit als String */
extern const char *Now(void);

/******************************************************************************/
/*                           GMP-LIB Hilfsfunktionen                          */
/******************************************************************************/

/* Konvertiert eine gegebene Langzahl in einen uint8_t-Array */
extern uint8_t * mpz_t2Ubyte(mpz_t a, unsigned int ubyteSize);

/* Speichert eine Langzahl in einem Array fester Länge */
void store_mpz(uint8_t *data, int dlen, mpz_t m);


#ifndef LTC_SHA256
struct sha256_state {
    uint64_t length;
    uint32_t state[8], curlen;
    unsigned char buf[64];
};
#endif
#ifndef LTC_MD5
struct md5_state {
    uint64_t length;
    uint32_t state[4], curlen;
    unsigned char buf[64];
};
#endif
#if !(defined(LTC_MD5)) || !(defined(LTC_SHA256))
typedef union Hash_state {
    char dummy[1];
    struct md5_state   md5;
    struct sha256_state sha256;
    void *data;
} hash_state;
#endif
void MD5Init(hash_state *mdContext);
void MD5Update(hash_state *mdContext, unsigned const char *inbuf, unsigned int len);
void MD5Final(unsigned char digest[16], hash_state *mdContext);

void SHA256Init ( hash_state *mdContext);
void SHA256Update (hash_state *mdContext, unsigned const char *inBuf,
		   unsigned int inLen);
void SHA256Final (unsigned char digest[32], hash_state *mdContext);


// AES
typedef void *aeskey;

aeskey aes_setup(const unsigned char *key, int keylen);
// Return 1 when error
int aes_enc(const unsigned char *pt, unsigned char *ct, aeskey key);
int aes_dec(const unsigned char *ct, unsigned char *pt, aeskey key);
void aes_free(aeskey k);

typedef void *aes_ctr_state;
aes_ctr_state aes_init_ctr(const unsigned char *key, int keylen, const unsigned char *iv);
void aes_do_ctr(const unsigned char *pt, unsigned char *ct, int len, aes_ctr_state state);
void aes_finish_ctr(aes_ctr_state state);

#endif
