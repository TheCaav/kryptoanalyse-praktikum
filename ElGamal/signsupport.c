/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Proktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 7: El-Gamal-Signatur                              *
**                                                           *
**************************************************************
**
** signsupport.c: Laden der Personendaten und Erzeugen des MDC
**/

#include <sys/time.h>
#include <unistd.h>
#include "sign.h"

/*
 * Generate_MDC( msg, P, mdc ) :
 *
 *   Berechnet die MDC zur Nachricht MSG. Der zu unterschreibende Teil 
 *   von MSG (ist abhängig vom Typ) wird als Byte-Array interpretiert
 *   und darüber der MDC berechnet. P ist der globale El-Gamal-Modulus.
 *
 * ACHTUNG: msg.type muß unbedingt richtig gesetzt sein!
 */

void Generate_MDC( const Message *msg, mpz_t p, mpz_t mdc)
  {
    hash_state m;

    uint8_t hash[32];

    int len, j;
    mpz_t h;
    const uint8_t *ptr;

    switch (msg->typ) {
      case ReportRequest:
        ptr = (const uint8_t *) &msg->body.ReportRequest;
	len = sizeof(msg->body.ReportRequest.Name);
	break;
      case ReportResponse:
	ptr = (const uint8_t *) &msg->body.ReportResponse.Report;
	len = sizeof(String)*msg->body.ReportResponse.NumLines;
	break;
      case VerifyRequest:
	ptr = (const uint8_t *) &msg->body.VerifyRequest.Report;
	len = sizeof(String)*msg->body.VerifyRequest.NumLines;
	if (len>sizeof(String)*MaxLines) len=sizeof(String)*MaxLines;
	break;
      case VerifyResponse:
	ptr = (const uint8_t *) &msg->body.VerifyResponse.Res;
	len = sizeof(msg->body.VerifyResponse.Res);
	if (len>sizeof(String)*MaxLines) len=sizeof(String)*MaxLines; 
	break;
      default :
	fprintf(stderr,"GENERATE_MDC: Illegaler Typ von Nachricht!\n");
	exit(20);
	break;
    }

    SHA256Init (&m);
    SHA256Update (&m, (const unsigned char *) ptr, len);
    SHA256Final (hash, &m);

    //LInitNumber(mdc,nbits,0);
		//LMakeZero(mdc);
		mpz_init_set_ui(mdc, 0);    
		mpz_init(h);

    for (j=0; j<32; j++) {
			mpz_set_ui(h, hash[j]);
			mpz_mul_2exp(h, h, j*8);	// h <<= i*8
			mpz_add(mdc, mdc, h);
    }

    for (j=0; j<8; j++)
      //LModSquare(mdc,mdc,p);
			mpz_powm_ui(mdc, mdc, 2, p);

  }



/*
 * Get_Public_Key(name,y) :
 *
 *  Sucht in der systemweiten Tabelle den öffentlichen Schlüssel des
 *  Teilnehmers NAME und speichert ihn in Y.
 *  
 * RETURN-Code: 1 bei Erfolg, 0 sonst.
 */

int Get_Public_Key( const String name, mpz_t y)
{
	FILE *f;
	char *filename;
	const char *root;
	char *line = NULL;
	size_t *bufsize = malloc(sizeof(int));
	*bufsize = 0;
	int found = 0;

	if (!(root=getenv("PRAKTROOT"))) if (!(root=getenv("HOME"))) root="";
	filename=concatstrings(root,"/public_keys.data",NULL);
	if (!(f=fopen(filename,"r"))) {
		fprintf(stderr,"GET_PUBLIC_KEY: Kann die Datei %s nicht öffnen: %s\n",filename,strerror(errno));
		exit(20);
	}
	free(filename);

	while (!feof(f) && getline(&line,bufsize,f)>0 && !(found=!(strcmp(line,name))));
	if(found) {
		getline(&line,bufsize,f);
		mpz_set_str(y, line, 16);
		fclose(f);
		return 1;
	} else {
		fprintf(stderr,"GET_PUBLIC_KEY: Benutzer \"%s\" nicht gefunden\n",name);
	}
	fclose(f);
	return 0;
}


/*
 * Get_Privat_Key(filename,p,w,x) :
 *
 *  Läd den eigenen geheimen Schlüssel nach X. Die globalen (öffentlichen)
 *  Daten P und W werden ebenfalls aus dieser Datei geladen.
 *  FILENAME ist der Name der Datei, in der der geheime Schlüssel gespeichert
 *  ist. Wird NULL angegeben, so wird die Standarddatei "./privat_key.data" benutzt.
 *
 * RETURN-Code: 1 bei Erfolg, 0 sonst.
 */

int Get_Privat_Key(const char *filename, mpz_t p, mpz_t w, mpz_t x)
  {
    FILE *f;
    SecretData sd;

    if (!filename) filename = concatstrings(getenv("HOME"),"/private_key.data",NULL);
    if (!(f=fopen(filename,"r"))) {
      fprintf(stderr,"GET_PRIVAT_KEY: Kann die Datei %s nicht öffnen: %s\n",filename,strerror(errno));
      return 0;
    }

    if (fread(&sd,sizeof(sd),1,f)!=1) {
      fprintf(stderr,"GET_PRIVAT_KEY: Fehler beim Lesen der Datei %s\n",filename);
      fclose(f);
      return 0;
    }
    fclose(f);
    /*LCpy(x,&sd.x);
    LCpy(p,&sd.p);
    LCpy(w,&sd.w);*/
		mpz_set(p, sd.p);
		mpz_set(w, sd.w);
		mpz_set(x, sd.x);

    return 1;
  }

void LXRand (mpz_t max, mpz_t z)
  {
    mpz_t x, h;
    int i;

    mpz_init_set_ui(z, 0);

    mpz_init_set_ui(x, 1);
    mpz_init(h);

    for (i = 0; i == mpz_sizeinbase(z, 2) / 8; i++) {
	mpz_set_ui(h, cs_rand_byte());
	mpz_mul_2exp(h, h, i*8);	// h <<= i*8
	mpz_add(z, z, h);
    }
    mpz_mul(z, z, x);
    mpz_mod(z, z, max);
  }

/*
 * Get_Private_Key(filename,p,w,x) :
 *
 *  Läd den eigenen geheimen Schlüssel nach X. Die globalen (öffentlichen)
 *  Daten P und W werden ebenfalls aus dieser Datei geladen.
 *  FILENAME ist der Name der Datei, in der der geheime Schlüssel gespeichert
 *  ist. Wird NULL angegeben, so wird die Standarddatei "./privat_key.data" benutzt.
 *
 * RETURN-Code: 1 bei Erfolg, 0 sonst.
 */

int Get_Private_Key(const char *filename, mpz_t p, mpz_t w, mpz_t x)
{
	FILE *f;
	char *line = NULL;
	size_t *bufsize = malloc(sizeof(int));
	*bufsize = 0;

	if (!filename) filename = concatstrings(getenv("HOME"),"/private_key.data",NULL);
	if (!(f=fopen(filename,"r"))) {
		fprintf(stderr,"GET_PRIVATE_KEY: Kann die Datei %s nicht öffnen: %s\n",filename,strerror(errno));
		return 0;
	}
	if(getline(&line,bufsize,f) <= 0 || mpz_set_str(p, line, 16)
			|| getline(&line,bufsize,f) <= 0 || mpz_set_str(w, line, 16)
			|| getline(&line,bufsize,f) <= 0 || mpz_set_str(x, line, 16)) {
		fprintf(stderr,"GET_PRIVAT_KEY: Fehler beim Lesen der Datei %s\n",filename);
		fclose(f);
		return 0;
	}
	fclose(f);
	return 1;
}

