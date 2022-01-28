/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**         Praktikum "Kryptoanalyse"                         *
**                                                           *
** Versuch 1: Klassische Chiffrierverfahren                  *
**                                                           *
**************************************************************
**
** vigenere.c: Implementierung einer Vigenere-Chiffre
**/

#include <stdio.h>
#include <stdlib.h>
#include <praktikum.h>

/*********************  Globale Hilfsbvariabeln  *******************/
String Key;     /* Schlüssel */
int keyIndex = 0;
int keyLength;

/*
 * int Encipher(int c) : Interpretiert C als Zeichen, verschlüsselt es nach der
 *                       Methode von Vigenere und gibt das Ergebnis als Resultat
 *                       zurück.
 */

static int Encipher(int c)
  {
    int ciph = c;
    if (c >= 65 && c <= 90) {
        ciph = c + Key[keyIndex];
        if (ciph > 90) {
            ciph = 65 + ciph - 91;
        }
        keyIndex = (keyIndex + 1) % keyLength;
    }
    return ciph;
  }


/*
 * int Decipher(int c) : Interpretiert C als Zeichen, entschlüsselt es nach der
 *                       Methode von Vigenere und gibt das Ergebnis als Resultat
 *                       zurück.
 */

static int Decipher(int c)
  {
    int ciph = c;
    if (c >= 65 && c <= 90) {
        ciph = c - Key[keyIndex];
        if (ciph < 65) {
            ciph = 90 + ciph - 64;
        }
        keyIndex = (keyIndex + 1) % keyLength;
    }
    return ciph;
  }


/*
 * main(argc,argv) : Das Hauptprogramm, welches beim Aufruf von VIGENERE aufgerufen wird.
 *   ARGC ist die Anzahl der in der Kommandozeile angegebenen Argumente plus 1, ARGV ist
 *   ein Feld von Zeigern auf eben diese Argumente. ARGV[1] ist das erste usw.
 *   ARGV[0] enthält den Namen des Programms.
 */

int main(int argc, char **argv)
{
  String infilename,outfilename,help,zeile;
  int decipher;
  /***** weitere (lokale) Hiflsbvariabeln *******/

  FILE *infile,*outfile;

  /* Wenn die Ein- bzw. Ausgabedatei oder der Schlüssel nicht in der
   * Kommandozeile angegeben wurden, fragen wir einfach nach .... */
  if (argc<2) readline("Eingabefile : ",infilename,sizeof(infilename));
  else strncpy(infilename,argv[1],sizeof(infilename));
  if (argc<3) readline("Ausgabefile : ",outfilename,sizeof(outfilename));
  else strncpy(outfilename,argv[2],sizeof(outfilename));
  if (argc<4) readline("Schluessel  : ",Key,sizeof(Key));
  else strncpy(Key,argv[3],sizeof(Key));

  if (argc<5) {
    do {
      readline("V)er- oder E)ntschlüsseln : ",help,sizeof(help));
      string_to_upper(help);
    }
    while (strlen(help)!=1 && help[0]!='V' && help[0]!='E');
    decipher = help[0]=='E';
  }
  else {
    if (!strncmp(argv[4],"encipher",strlen(argv[4]))) decipher = 0;
    else if (!strncmp(argv[4],"decipher",strlen(argv[4]))) decipher = 1;
    else {
      fprintf(stderr,"FEHLER: Unbekannter Modus, 'encipher' oder 'decipher' erwartet.\n");
      exit(20);
    }
  }
  string_to_upper(Key);
  for (int i = 0; Key[i] != 0; i++) {
      Key[i] = Key[i] - 65;
      keyLength = i + 1;
  }

  /* Öffnen der Dateien:
   *  `fopen' gibt im Fehlerfall einen NULL-Pointer zurück. Kann die Datei
   *  geöffnet werden, so wird der von `fopen' zurückgelieferte FILE-Pointer
   *  als Argument bei den Aufrufen `fgets', `fprintf', `fclose' usw. 
   *  zur Identifizierung der Datei angegeben.
   */
  if (!(infile=fopen(infilename,"r"))) {
    fprintf(stderr,"FEHLER: Eingabefile %s kann nicht geöffnet werden: %s\n",infilename,strerror(errno));
    exit(20);
  }
  if (!(outfile=fopen(outfilename,"w"))) {
    fprintf(stderr,"FEHLER: Ausgabefile %s kann nicht geöffnet werden: %s\n",outfilename,strerror(errno));
    exit(20);
  }

  /* Belegung der Variablen:
   *  infilename : Name der Eingabedatei 
   * outfilename : Name der Ausgabedatei
   *      infile : `Datei-Bezeichner', der die Eingabedatei repräsentiert.
   *     outfile : `Datei-Bezeichner', der die Ausgabedatei repräsentiert.
   *         Key : Schlüssel, nach Großschrift gewandelt
   *    decipher : Flag, == 1 im Entschlüsselungsmodus, ansonsten 0.
   */

  do {
    fgets(zeile,sizeof(zeile),infile);
    if (!feof(infile)) {
      strip_crlf(zeile);
      string_to_upper(zeile);

      for (int i = 0; zeile[i] != 0; i++) {
          if (decipher) {
              zeile[i] = Decipher(zeile[i]);
          } else {
              zeile[i] = Encipher(zeile[i]);
          }
      }
      fprintf(outfile,"%s\n",zeile);
    }
  }
  while (!feof(infile));

  /* Schließen der Ein- und Ausgabedateien */
  fclose(infile);
  fclose(outfile);

  return 0;
}
