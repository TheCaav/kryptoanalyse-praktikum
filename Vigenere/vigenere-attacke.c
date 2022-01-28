/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**         Praktikum "Kryptoanalyse"                         *
**                                                           *
** Versuch 1: Klassische Chiffrierverfahren                  *
**                                                           *
**************************************************************
**
** vigenere_attacke.c: Brechen der Vigenere-Chiffre
**/

#include <stdio.h>
#include <stdlib.h>
#include <praktikum.h>

#define GNUPLOT_CMD_FILENAME "gnuplot.in.cmd" /* Name fuer das erzeugte
						 gnuplot-Kommandofile */
#define GNUPLOT_DATA_FILENAME "gnuplot.in.data" /* Name fuer Datenfile */

#define NUMCHARS    26       /* Anzahl der Zeichen, die betrachtet werden ('A' .. 'Z') */
#define MaxFileLen  32768    /* Maximale Größe des zu entschlüsselnden Textes */
#define MAXPERIOD   200      /* Maximale Periodenl"ange, f"ur die die
				Autokorrelation berechnet wird */

const char *StatisticFileName = "statistik.data";  /* Filename der Wahrscheinlichkeitstabelle */
const char *WorkFile          = "testtext.ciph";   /* Filename des verschlüsselten Textes */

double PropTable[NUMCHARS]; /* Tabellke mit den Zeichenwahrscheinlichkeiten.
			     * ProbTable[0] == 'A', PropTable[1] == 'B' usw. */
char TextArray[MaxFileLen]; /* die eingelesene Datei */
int TextLength;             /* Anzahl der gültigen Zeichen in TextArray */

double AutoCor[MAXPERIOD+1]; /* Normierte Autokorrelationen */
int Period;                  /* berechnete Periodenlaenge */

/*--------------------------------------------------------------------------*/

/*
 * GetStatisticTable(): Liest die Statistik-Tabelle aus dem File
 * STATISTICFILENAME in das globale Array PROPTABLE ein.
 */

static void GetStatisticTable(void)
  {
    FILE *inp;
    int i;
    char line[64];

    if (!(inp=fopen(StatisticFileName,"r"))) {
      fprintf(stderr,"FEHLER: File %s kann nicht geöffnet werden: %s\n",
	      StatisticFileName,strerror(errno));
      exit(20);
    }

    for (i=0; i<TABSIZE(PropTable); i++) {
      fgets(line,sizeof(line),inp);
      if (feof(inp)) {
        fprintf(stderr,"FEHLER: Unerwartetes Dateieine in %s nach %d Einträgen.\n",
		StatisticFileName,i);
	exit(20);
      }
      PropTable[i] = atof(line);
    }
    fclose(inp);
  }

/*-------------------------------------------------------------------------*/

/* GetFile(void) : Ließt den verschlüsselten Text aus dem File
 *   WORKFILE zeichenweise in das globale Array TEXTARRAY ein und zählt
 *   TEXTLENGTH für jedes Zeichen um 1 hoch.
 *   Eingelesen werden nur Buchstaben. Satz- und Sonderzeichen werden weggeworfen,
 *   Kleinbuchstaben werden beim Einlesen in Großbuchstaben gewandelt.
 */

static void GetFile(void)
  {
    FILE *inp;
    char c;

    if (!(inp=fopen(WorkFile,"r"))) {
      fprintf(stderr,"FEHLER: File %s kann nicht geöffnet werden: %s\n",
	      WorkFile,strerror(errno));
      exit(20);
    }

    TextLength=0;
    while (!feof(inp)) {
      c = fgetc(inp);
      if (feof(inp)) break;
      if (c>='a' && c<='z') c -= 32;
      if (c>='A' && c<='Z') {
	if (TextLength >= sizeof(TextArray)) {
	  fprintf(stderr,"FEHLER: Eingabepuffer nach %d Zeichen übergelaufen!\n",TextLength);
	  exit(20);
	}
        TextArray[TextLength++] = c;
      }
    }
    fclose(inp);
  }


/*--------------------------------------------------------------------------*/

/*
 * CountChars( int start, int offset, int h[] )
 *
 * CountChars zählt die Zeichen (nur Buchstaben!) im globalen Feld
 * TEXTARRAY. START gibt an, bei welchen Zeichen (Offset vom Begin der
 * Tabelle) die Zählung beginnen soll und OFFSET ist die Anzahl der
 * Zeichen, die nach dem 'Zählen' eines Zeichens weitergeschaltet
 * werden soll. 'A' wird in h[0], 'B' in h[1] usw. gezählt.
 *  
 *  Beispiel:  OFFSET==3, START==1 --> 1,  4,  7,  10, ....
 *             OFFSET==5, START==3 --> 3,  8, 13,  18, ....
 *
 * Man beachte, daß das erste Zeichen eines C-Strings den Offset 0 besitzt!
 */

static void CountChars( int start, int offset, int h[NUMCHARS])
  {
    int i;
    char c;

    for (i=0; i<NUMCHARS; i++) h[i] = 0;
    for (i=start; i<TextLength; i = i + offset) {
        c = TextArray[i];
        if (c >= 65 && c <= 90) {
            h[c - 65]++;
        }
    }
  }

/*
 * AutoCorrelation (int d)
 *
 * AutoCorrelation berechnet die Autokorrelation im Text mit der Verschiebung
 * (Periode) d.
 *
 * Als Metrik soll die Funktion eingesetzt werden, die bei gleichen Zeichen
 * 0, sonst 1 ergibt. Die Autokorrelation muss hier *nicht* normiert werden.
 * dies geschieht unten in main() im Rahmenprogramm.
 *
 * Der Text steht im Feld TextArray und enthaelt TextLength Zeichen.
 *
 * Das Ergebnis soll als Returnwert zur"uckgegeben werden.
 */

static double AutoCorrelation (int d)
{
  int sum = 0;
  for (int i = 0; i < TextLength - i; i++) {
    if (TextArray[i] != TextArray[i+d]) {
        sum++;
    }
  }
  return sum;
}

/*
 * CalcPeriod ()
 *
 * Berechnet (oder liest vom Benutzer ein) die Periode der Chiffre.
 * Das Ergebnis soll in der globalen Variable Period gespeichert werden.
 * Zum Beispiel kann dazu das Array AutoCor, das die vorher berechneten
 * Autokorrelationen (normiert!) enth"alt.
 */

static void CalcPeriod (void)
{
  /**String size;
  readline("Größe des Schlüssels? ",size,sizeof(size));
  Period = atoi(size);
  printf("You inserted: %d", Period);*/
  Period = getLowest(AutoCor, 1, MAXPERIOD + 1); // Not perfect but user should see if there is a repeating pattern in the solution
}

/**
 * Calculates lowest value in a given array and returns index
 */
int getLowest(double array[], int start, int length) {
    int lowest = TextLength;
    double val = 1;
    for (int i = start; i < length; i++) {
      if (array[i] < val) {
          val = array[i];
          lowest = i;
      }
    }
    return lowest;
}

/*------------------------------------------------------------------------------*/

int main(int argc, char **argv)
{

  GetStatisticTable();     /* Wahrscheinlichkeiten einlesen */
  GetFile();               /* zu bearbeitendes File einlesen */

  {
    int i;
    for (i = 0; i <= MAXPERIOD; i++) {
      AutoCor [i] = (double) AutoCorrelation (i) / (TextLength - i);
    }
  }

  /* Now prepare gnuplot */
  {
    FILE *f;
    int i;

    f = fopen (GNUPLOT_CMD_FILENAME, "w");
    if (! f) {
      perror ("Error creating file " GNUPLOT_CMD_FILENAME);
      exit (2);
    }
    fprintf (f, "set print \"-\"\n");             // make gnuplot print to stdout instead of stderr
    fprintf (f, "plot [1:%d] \"%s\" using 0:1 with lines\n", MAXPERIOD,
	     GNUPLOT_DATA_FILENAME);
    fprintf (f, "print \"Bitte Return druecken...\"\npause -1\n");
    fclose (f);
    f = fopen (GNUPLOT_DATA_FILENAME, "w");
    if (! f) {
      perror ("Error creating file " GNUPLOT_DATA_FILENAME);
      exit (2);
    }
    for (i = 0; i <= MAXPERIOD; i++) {
      fprintf (f, "%f\n", AutoCor[i]);
    }
    fclose (f);
  }

  /* Now call it */

  system ("gnuplot " GNUPLOT_CMD_FILENAME);

  CalcPeriod ();

  /*****************  Aufgabe 4 *****************/

  printf("Period is: %d\n", Period);
  for (int i = 0; i < Period; i++) {
      int h[NUMCHARS];
      CountChars(i, Period, h);
      double h2[NUMCHARS];
      for (int k = 0; k < NUMCHARS; k++) { // calculate relative occurences
          h2[k] = ((double) h[k]) / ((double) TextLength / (double) Period);
          //printf("h_%d[%d] = %f, ", i, k, h2[k]);
      }

      //printf("\n");
      double d[NUMCHARS];
      for (int k = 0; k < NUMCHARS; k++) {
          double korr = 0;
          d[k] = 0;
          for (int j = 0; j < NUMCHARS; j++) {
              int ind = (k + j) % NUMCHARS;
              double diff = PropTable[j] - h2[ind];
              korr += diff * diff;
          }
          d[k] = korr;
      }
      int verschiebung = getLowest(d, 0, NUMCHARS);
      

      printf("%c", verschiebung + 65);
  }

  return 0;
}
