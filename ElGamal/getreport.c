/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Proktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 7: El-gamal-Signatur                              *
 **                                                           *
 **************************************************************
 **
 ** getreport.c: Rahmenprogramm für den Signatur-Versuch
 **/

#include "sign.h"
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <gmp.h>

static mpz_t p;
static mpz_t w;

const char *factorlist_hex[] = {
	"5", "7", "9", "B", "D", "11","13","17","1D","1F","25","29",
	"2B","2F","35","3B","3D","40","43","47","49","4F","53","59",
	"61","65","67","6B","6D","71","7F","83","89","8B","95","97",
	"9D","A3","A7","AD","B3","B5","BF","C1","C5","C7","D3","DF",
	"E3","E5","E9","EF","F1","FB","101","107","10D","10F","115",
	"119","11B","125","133","137","139","13D","14B",
	"10000000F", "12000050F", 0
};

int nfactors;
mpz_t *factorlist;              /* Zugriff hierauf wie auf Array. Index 0<=i<nfactors */

/*
 * init_factors() : Füllt die interne factorlist mit Faktoren.
 */
static void init_factors(void)
{
	int i;
	mpz_t tmp;

	for (nfactors=0; factorlist_hex[nfactors]; nfactors++);
	factorlist = calloc(nfactors, sizeof(mpz_t));
	mpz_init(tmp);
	mpz_set_ui(tmp, 1);
	for (i = 0; i < nfactors; i++) {
		mpz_init(factorlist[i]);
		mpz_set_str(factorlist[i], factorlist_hex[i], 16);
		mpz_mul(tmp, tmp, factorlist[i]);
	}
	mpz_add_ui(tmp, tmp, 1);
	if (mpz_cmp(tmp, p)) {
		printf ("FATAL: Faktoren stammen nicht von p-1!\n");
		exit (1);
	}
	mpz_clear(tmp);
}

typedef struct giTuple {
	int i;
	mpz_t gi;
} giTuple;

int giTupleCmp(const void *a, const void *b) {
	return mpz_cmp(((struct giTuple*)a)->gi, ((struct giTuple*)b)->gi);
}

int giComp(const void *a, const void *b) {
	return mpz_cmp(*(mpz_t*)a, ((struct giTuple*)b)->gi);
}

/*
 * babyStepGiantStep(mpz_t x_i, mpz_t a_i, mpz_t w_i, mpz_t p_i):
 *
 * Berechnet x_i so dass a_i = w_i ^ x_i mod p.
 */
static void babyStepGiantStep(mpz_t x_i, mpz_t a_i, mpz_t w_i, mpz_t p_i)
{
	mpz_t m, pMOne;
	mpz_inits(m, pMOne, NULL);
	int exact;
	exact = mpz_root(m, p_i, 2);
	if (exact == 0) {
		mpz_add_ui(m, m, 1);
	}

	// create list of i and g^i and populate it
	giTuple* giList;
	giList = calloc(mpz_get_ui(m) + 1, sizeof(giTuple));
	for (int i = 0; i <= mpz_get_ui(m); i++) {
		giList[i].i = i;
		mpz_init(giList[i].gi);
		mpz_powm_ui(giList[i].gi, w_i, i, p); // giList[i].gi = w_i ^ i mod |G|
	}
	qsort(giList, mpz_get_ui(m)+1, sizeof(giTuple), giTupleCmp);
	
	mpz_t gHighM, z;
	mpz_init(gHighM);
	mpz_powm(gHighM, w_i, m, p);
	if (mpz_invert(gHighM, gHighM, p) == 0) printf("No inverse\n"); // gHighM = g^-m
	mpz_init_set(z, a_i);

	giTuple* target;
	int j;
	for (j = 0; j <= mpz_get_ui(m); j++) {
		target = (giTuple*) bsearch(z, giList, mpz_get_ui(m)+1, sizeof(giTuple), giComp);
		if (target != NULL) {
			break;
		}
		mpz_mul(z, z, gHighM);
		mpz_mod(z, z, p);
	}
	if (target == NULL) {
		printf("x_i not found\n");
		x_i = NULL;
	} else {
		mpz_t tmp;
		mpz_inits(tmp, NULL);
		mpz_mul_ui(tmp, m, j);
		mpz_add_ui(x_i, tmp, target->i);
		mpz_mod(x_i, x_i, p);
		mpz_clear(tmp);
	}
	free(giList);
	mpz_clears(m, gHighM, z, NULL);
}

/*
 * dlogP(x, y):
 *
 * Berechnet x, wobei y = w ^ x mod p mithilfe der Faktorisierung von p - 1.
 */
static void dlogP(mpz_t x, mpz_t y)
{
	init_factors();
	
	mpz_t a_i[nfactors];
	mpz_t alpha, w_i, y_i, exp_i, pMinusOne;
	mpz_inits(alpha, w_i, y_i, exp_i, pMinusOne, NULL);
	mpz_sub_ui(pMinusOne, p, 1);
	for (int i = 0; i < nfactors; i++) {
		mpz_cdiv_q(exp_i, pMinusOne, factorlist[i]);
		mpz_powm(w_i, w, exp_i, p);
		mpz_powm(y_i, y, exp_i, p);	
		mpz_init(a_i[i]);
		babyStepGiantStep(a_i[i], y_i, w_i, factorlist[i]);
	}

	for (int i = 0; i < nfactors; i++) {
		mpz_t tmp;
		mpz_t tmpMod;
		mpz_init_set(tmp, a_i[i]);
		mpz_init(tmpMod);

		for (int j = 0; j < nfactors; j++) {
			if (j == i) continue;
			mpz_mul(tmp, tmp, factorlist[j]);
			mpz_invert(tmpMod, factorlist[j], factorlist[i]); // tmpMod = factorj^-1 mod factorlisti
			mpz_mul(tmp, tmp, tmpMod);
		}
		mpz_add(alpha, alpha, tmp);
		mpz_clears(tmp, tmpMod, NULL);
	}

	mpz_mod(alpha, alpha, pMinusOne);
	mpz_set(x, alpha);
	mpz_clears(alpha, w_i, y_i, exp_i, pMinusOne, NULL);
}


/*
 * Verify_Sign(mdc,r,s,y) :
 *
 *  überprüft die El-Gamal-Signatur R/S zur MDC. Y ist der öffentliche
 *  Schlüssel des Absenders der Nachricht
 *
 * RETURN-Code: 1, wenn Signatur OK, 0 sonst.
 */
static int Verify_Sign(mpz_t mdc, mpz_t r, mpz_t s, mpz_t y)
{
	mpz_t tmp;
	mpz_t aPowerB;
	mpz_t mdcPowered;
	mpz_inits(tmp, aPowerB, mdcPowered, NULL);
	mpz_powm(mdcPowered, w, mdc, p);
	mpz_powm(tmp, y, r, p);
	mpz_powm(aPowerB, r, s, p);
	mpz_mul(tmp, tmp, aPowerB);
	mpz_mod(tmp, tmp, p);

	int ret;

	if (mpz_cmp(mdcPowered, tmp) == 0) ret = 1;
	else ret = 0;

	mpz_clears(tmp, aPowerB, mdcPowered, NULL);
	return ret;
}


/*
 * Generate_Sign(m,r,s,x) : Erzeugt zu der MDC M eine El-Gamal-Signatur 
 *    in R und S. X ist der private Schlüssel
 */
static void Generate_Sign(mpz_t mdc, mpz_t r, mpz_t s, mpz_t x)
{
	srand(time(NULL));
	int random = rand();
	
	gmp_randstate_t randState;
	gmp_randinit_default(randState);
	gmp_randseed_ui(randState, random);

	mpz_t one, pMinusOne, gcd, mdcMod, e, a, tmp;
	mpz_inits(one, pMinusOne, gcd, mdcMod, e, a, tmp, NULL);
	mpz_set_ui(one, 1);
	mpz_sub(pMinusOne, p, one);

	// choose random, uniform e such that gcd(e, p-1) = 1
	do {
		mpz_urandomm(e, randState, pMinusOne);
		mpz_gcd(gcd, pMinusOne, e);	
	} while (mpz_cmp(gcd, one) != 0);

	// calculate a = g^e
	mpz_powm(a, w, e, p);
	
	// calculate b as b = (mdc-a*x)/e mod |G|
	mpz_mul(tmp, x, a);
	mpz_mod(tmp, tmp, pMinusOne);
	mpz_mod(mdcMod, mdc, pMinusOne);
	mpz_sub(tmp, mdcMod, tmp);
	mpz_mod(tmp, tmp, pMinusOne);
	mpz_invert(e, e, pMinusOne);
	mpz_mul(tmp, tmp, e);
	mpz_mod(tmp, tmp, pMinusOne);

	mpz_set(r, a);
	mpz_set(s, tmp);
	mpz_clears(one, pMinusOne, gcd, e, a, mdcMod, tmp, NULL);
}

int main(int argc, char **argv)
{
	Connection con;
	int cnt,ok;
	Message msg;
	mpz_t x, Daemon_y, Daemon_x, mdc, sign_s, sign_r;
	char *OurName;

	mpz_init(x);
	mpz_init(Daemon_y);
	mpz_init(Daemon_x);
	mpz_init(mdc);
	mpz_init(sign_s);
	mpz_init(sign_r);
	mpz_init(p);
	mpz_init(w);

	const char *keyfile = NULL;
	char c;
	while ( (c=getopt(argc,argv,"f:"))!=-1 ) {
	  switch (c) {
	    case 'f' :
	      keyfile = optarg;
	    break;
	  }
	}

	/**************  Laden der öffentlichen und privaten Daten  ***************/
	if (!Get_Private_Key(keyfile, p, w, x) || !Get_Public_Key(DAEMON_NAME, Daemon_y)) exit(0);


	/********************  Verbindung zum Dämon aufbauen  *********************/
	OurName = "calvin"; /* gibt in Wirklichkeit Unix-Gruppenname zurück! */
	if (!(con=ConnectTo(OurName,DAEMON_NAME))) {
		fprintf(stderr,"Kann keine Verbindung zum Daemon aufbauen: %s\n",NET_ErrorText());
		exit(20);
	}


	/***********  Message vom Typ ReportRequest initialisieren  ***************/
	msg.typ  = ReportRequest;                       /* Typ setzten */
	strcpy(msg.body.ReportRequest.Name,OurName);    /* Gruppennamen eintragen */
	Generate_MDC(&msg, p, mdc);                     /* MDC generieren ... */
	Generate_Sign(mdc, sign_r, sign_s, x);          /* ... und Nachricht unterschreiben */
	strcpy(msg.sign_r, mpz_get_str(NULL, 16, sign_r));
	strcpy(msg.sign_s, mpz_get_str(NULL, 16, sign_s));

	/*************  Machricht abschicken, Antwort einlesen  *******************/
	Transmit(con,&msg,sizeof(msg));
	ReceiveAll(con,&msg,sizeof(msg));


	/******************  Überprüfen der Dämon-Signatur  ***********************/
	printf("Nachricht vom Dämon:\n");
	for (cnt=0; cnt<msg.body.ReportResponse.NumLines; cnt++) {
		printf("\t%s\n",msg.body.ReportResponse.Report[cnt]);
	}

	Generate_MDC(&msg, p, mdc);
	mpz_set_str(sign_r, msg.sign_r, 16);
	mpz_set_str(sign_s, msg.sign_s, 16);
	ok=Verify_Sign(mdc, sign_r, sign_s, Daemon_y);
	if (ok) printf("Dämon-Signatur ist ok!\n");
	else printf("Dämon-Signatur ist FEHLERHAFT!\n");

	dlogP(Daemon_x, Daemon_y);
	strcpy(msg.body.VerifyRequest.Report[0], "Praktikum bestanden");
	strcpy(msg.body.VerifyRequest.Report[1], "Volle Punktzahl");
	strcpy(msg.body.VerifyRequest.Report[2], "");
	strcpy(msg.body.VerifyRequest.Report[3], "- Definitiv der Daemon");
	msg.body.VerifyRequest.NumLines = 4;

	msg.typ = VerifyRequest;
	Generate_MDC(&msg, p, mdc);	
	Generate_Sign(mdc, sign_r, sign_s, Daemon_x);
	
	ok=Verify_Sign(mdc, sign_r, sign_s, Daemon_y);
	if (ok) printf("Dämon-Signatur ist erfolgreich gefälscht!\n");
	else printf("Dämon-Signatur ist nicht erfolgreich gefälscht!\n");

	mpz_get_str(msg.sign_r, 16, sign_r);
	mpz_get_str(msg.sign_s, 16, sign_s);
	
	printf("Zu sendende Nachricht:\n");
	for (cnt=0; cnt<msg.body.VerifyRequest.NumLines; cnt++) {
		printf("\t%s\n",msg.body.VerifyRequest.Report[cnt]);
	}
	
	Transmit(con,&msg,sizeof(msg));
	ReceiveAll(con,&msg,sizeof(msg));

	printf("%s\n", msg.body.VerifyResponse.Res);
	
	mpz_clears(x, Daemon_y, Daemon_x, mdc, sign_s, sign_r, p, w, NULL);
	return 0;
}


