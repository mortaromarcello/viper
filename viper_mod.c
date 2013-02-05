#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <openssl/des.h>
#include <unistd.h>

/*                                                                    */

//#define DEBUG				0
#define DEFAULTPWLENGTH		8
#define MAXPASSWDLENGTH		16
#define MAXENCPWDLENGTH		254
#define TIMECHECK			1000000
#define FIN_IDENT			"--viper_final--"
#define SCREENWIDTH			80
#define SCREENHEIGTH		24
#define MAXSTR				255
#define NCHRUSER			80

const char *charsets[] = {
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}\\|;\':\",./<>?`",
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
		"abcdefghijklmnopqrstuvwxyz1234567890",
		"abcdefghijklmnopqrstuvwxyz",
		"1234567890"
};

struct crack_input
{
	char *ci_user;		// username
	char *ci_pass;		// encrypted password
	char *ci_dpas;		// decrypted password
	char *ci_cset;		// characterset to use
	char ci_rf;			// runtime limit
	int  ci_pwl;		// password max length
	int  ci_pws;		// password min length
	int  ci_ui;			// console update interval
	char *ci_dnum;		// status for each digit
	char *ci_pf;		// progressfile name
	int  ci_vo;			// verbose output
	int  ci_ht;			// halt option
};

/*                                                                    */

void convert(double, char *);
void chop(char *);
int crack_dict(struct crack_input *, char *);
int crack_bruteforce(struct crack_input *);
void help (void);
void the_res(struct crack_input *, struct tm);
double get_duration(time_t);

/*                                                                    */

void convert(double sec_dur, char * strf_duration)
{
	double x, y, yr_rest, d_rest, h_rest;
	int year, day, hour, min, sec;

	x = sec_dur / (double) 31536000;
	year = abs((int)x);
	y = year * (double) 31536000;
	yr_rest = sec_dur - y;

	x = yr_rest / (double) 86400;
	day = abs((int)x);
	y = day * (double) 86400;
	d_rest = yr_rest - y;

	x = d_rest / (double) 3600;
	hour = abs((int)x);
	y = hour * (double) 3600;
	h_rest = d_rest - y;

	x = h_rest / (double) 60;
	min = abs((int)x);
	y = (double) min * (double) 60;
	sec = (int) h_rest - y;

	if (year)
	{ sprintf(strf_duration, "%4.4dyrs:%3.3dd:%2.2dh", year, day, hour); }
	else
	{ sprintf(strf_duration, "%3.3dd:%2.2dh:%2.2dm:%2.2ds", day, hour, min, sec); }
}

void chop(char *word)
{
  int lenword;
  lenword=strlen(word);
  if( word[lenword-1] == '\n') 
    word[lenword-1] = '\0';
} 

double get_duration(time_t start_time)
{
	double val;
	time_t read_time;
	time(&read_time);
	val = difftime(read_time, start_time);
	return val;
}

int crack_dict(struct crack_input *lsf_out_ptr, char *dict)
{
	int i=0;
	char word[17] = "";
	char salt[2]  = "";
	char *hashguess = 0;
	char time_done[17];
	FILE *words;
	struct crack_input lsf_out;
	time_t start_time;

	time(&start_time);
	
	memcpy(&lsf_out, lsf_out_ptr, sizeof(struct crack_input));
	if (dict == 0)
	{
		if ((words = fopen("/usr/share/dict/words","r")) == NULL) /* open spelling dictionary */
		{
			printf("Error: Can't open /usr/share/dict/words!\n");
			exit (1);
		}
	}
	else
	{
		if ((words=fopen(dict, "r")) == NULL)
		{
			printf("Error: Can't open %s!\n", dict);
			exit (1);
		}
	}
	strncat(salt, lsf_out.ci_pass, 2);
	while( (fgets(word, 17, words)) != NULL)
	{
		chop(word);
		if(strcmp((hashguess = DES_crypt(word,salt)), lsf_out.ci_pass) == 0)
		{ /* guessed the password ? */
			printf("the password is: %s\n",word);
			fclose(words);
			strcpy(lsf_out.ci_dpas, word);
			the_res(lsf_out_ptr, *localtime(&start_time));
			return 0;
		}
		if(i%100 == 0)
		{
			convert(get_duration(start_time), time_done);
			printf("[ Word: %-15s | Hashguess: %-15s | Time: %-15s ]\n", word, hashguess, time_done);
			if(lsf_out.ci_rf)
			{
				if( (lsf_out.ci_rf*3600) <= (int) get_duration(start_time) )
				{
					printf("\n [ RunFor duration of %d hours expired ]\n",
							lsf_out.ci_rf);
					return 1;
				}
			}
		}
		i++;
	}
	printf("The password is not in the spelling dictionary.\n");
	fclose(words);
	return 1;
}

int crack_bruteforce(struct crack_input *lsf_out_ptr)
{
	struct crack_input lsf_out;
	memcpy(&lsf_out, lsf_out_ptr, sizeof(struct crack_input));
	int count				= 0;
	int cps					= 0;
	int varlen				= strlen(lsf_out.ci_cset);
	int startpws			= lsf_out.ci_pws;
	int passprg[lsf_out.ci_pwl-1];
	char * testpass;
	int on					= 0;
	int ui				 	= lsf_out.ci_ui*60;
	int uicount				= 0;
	/* debug only */
#ifdef DEBUG
	int rf					= lsf_out.ci_rf*60;
#endif
	char salt[2]			= "";
	int i, j, y, z, end 	= 0;
	int k					= 0;
	double tot_num			= 0;
	int time_loop			= 0;
	int lines_loop			= 0;
	char checkpass[17];						// cleartext passphrase
	struct tm start_time, last_time;		// time structs
	char time_togo[17];						// calculated time to run
	time_t read_time;						// actual time
	FILE * fp_pf;							// progressfile
	char time_done[17];						// passed time
	double duration;
	struct tm act_time;

	/* debug only */
#ifdef DEBUG
	printf("user>%s pass>%s cset>%s rf>%d pwl>%d pws>%d ui>%d dnum>%s pf>%s\n",
	lsf_out.ci_user,
	lsf_out.ci_pass, lsf_out.ci_cset, rf,
	lsf_out.ci_pwl, lsf_out.ci_pws, ui,
	lsf_out.ci_dnum, lsf_out.ci_pf);
#endif

	printf("Character set is %d chars long.\nCharacters used:%s\n", varlen, lsf_out.ci_cset);

	/* get current time */
	time(&read_time);
	start_time = *localtime(&read_time);
	last_time = start_time;
	printf("Starting crack on: %s", asctime(&start_time));

	/* go on with the show */
	if (strlen(lsf_out.ci_dnum))
	{
		char * pass;
		passprg[0]=atoi(strtok(lsf_out.ci_dnum, ",")); i=1;
		printf("Saved progress is: %d (%c)", passprg[0], lsf_out.ci_cset[passprg[0]]);
		while ( (pass = strtok(NULL, ",")) )
		{
			if (pass && atoi(pass) < 128){passprg[i]=atoi(pass);}
			printf(" %d (%c)", passprg[i], lsf_out.ci_cset[passprg[i]]); i++;
		}
		printf("\n");
		startpws = i;
		for ( j=i; j < lsf_out.ci_pwl; j++ ) { passprg[j] = 0;}
		on = 1;
	}

	strncat(salt, lsf_out.ci_pass, 2);

	/* debug only */
#ifdef DEBUG
	printf("Salt of the password %13s is: %s\n", lsf_out.ci_pass, salt);
#endif

	/* make new password */
	for ( i = startpws; i <= lsf_out.ci_pwl; i++ )
	{
		if (on) { on = 0; }
		else
		{
			for ( j=0; j < lsf_out.ci_pwl; j++ ) { passprg[j] = 0;}
		}
		tot_num = varlen;
		printf("Cracking for pass length %d", i);
		if(lsf_out.ci_vo)
		{
			int tc;
			for (tc=1; tc<i; tc++) { tot_num = tot_num * varlen; }
			printf (" (%g possibilities)", tot_num);
		}
		printf("\n");

		/* start loop for this length */
		while (passprg[0] != varlen)
		{
			count++;

			/* make actual password out of array */
			for (y=0; y < i; y++)
			{
				checkpass[y] = lsf_out.ci_cset[passprg[y]];
			}
			checkpass[y+1] = '\0';

			/* debug only */
#ifdef DEBUG
			for (z=0; z<= (sizeof(passprg)/sizeof(int)); z++)
			{ printf("[%.2d]", passprg[z]);}
			printf(" - phrase: %s", checkpass);
#endif
			/* Here is where the magic happens */
			//testpass = (char *) fcrypt(checkpass, salt);
			testpass = (char *) DES_crypt(checkpass, salt);

			/* debug only */
#ifdef DEBUG
			printf(" ---> testpwd is: %s\n", testpass);
#endif
			if (! strcmp(testpass, lsf_out.ci_pass))
			{
				/* debug only */
//#ifdef DEBUG
				printf("We got it!!!! ----> %s\n", checkpass);
//#endif
				strcpy(lsf_out.ci_dpas, checkpass);
				act_time=*localtime(&read_time);
				duration = (double) difftime(mktime(&act_time), mktime(&start_time));
				convert(duration, time_done);
				the_res(lsf_out_ptr, start_time);
				return 0;
			}

			/* debug only */
#ifdef DEBUG
			printf("count: %d\n", count);
#endif

			/* Time check */
			if (count == TIMECHECK)
			{
				double time_dif;
				time_loop++;
				time(&read_time);
				act_time=*localtime(&read_time);
				time_dif = difftime(mktime(&act_time), mktime(&last_time));
				uicount = uicount + count;

				/* debug only */
#ifdef DEBUG
				printf("[ act: %s | last: %s | diff: %lf | uicount: %d ]\n",
							asctime(&act_time), asctime(&last_time), time_dif, uicount);
#endif

				/* update interval check - calculate duration and cps */
				if (time_dif >= ui)
				{
					duration = (double) difftime(mktime(&act_time), mktime(&start_time));
					last_time = act_time;
					cps = uicount / time_dif;
					convert(duration, time_done);

					/*  v1.4 add-on / time-remaining and percent calculation */
					if(lsf_out.ci_vo)
					{
						double pre, percent, left, i_sec;
						int width;
    					pre = tot_num / (double) TIMECHECK;
    					percent = (double) time_loop / pre;
    					percent = percent * (double) 10000;
    					percent = percent / (double) 100;
						left = tot_num - ((double) time_loop*(double) TIMECHECK);
   						i_sec = left / (double) cps;
  						convert(i_sec, time_togo);
						if (lines_loop == SCREENHEIGTH-2) {lines_loop = 0;}
						if(lines_loop == 0)
						{
							printf("\n[ Length: | Last:    | CPS:    | Time Spent:      | Time Remaining:  | Done:  ]\n");
							for (width=1; width < SCREENWIDTH; width++) { printf("-"); }
							printf("\n");
						}
						printf("[    %d    | %8s | %7d | %s | %s | %0#5.2f%c ]\n",
						i, checkpass, cps, time_done, time_togo, percent, '%' );
						lines_loop++;
					}
					else
					{
						printf("[ Length: %d | Last: %s | CPS: %d | Time: %s ]\n",
						i, checkpass, cps, time_done);
					}

					/* ## additional conditional routine : auto-save progress (v1.3) */
    				if(strlen(lsf_out.ci_pf))
					{
						char dnum[81]			= "";
						if ( (fp_pf = fopen(lsf_out.ci_pf, "w")) == NULL )
						{
							printf("Error: Can't open %s!\n", lsf_out.ci_pf);
							exit(-1); }

						for (k=0; k < i; k++)
						{
							/* debug only */
#ifdef DEBUG
							printf("dnum %d: %d\n", k, passprg[k]);
#endif

							sprintf(strchr(dnum, '\0'), "%d,", passprg[k]);
						}
						strcpy(strrchr(dnum, ','), "\0");

						fprintf(fp_pf, "--viper_prog--\n");
						fprintf(fp_pf, "%d\n", lsf_out.ci_pws);
						fprintf(fp_pf, "%d\n", lsf_out.ci_pwl);
						fprintf(fp_pf, "%s\n", lsf_out.ci_pass);
						fprintf(fp_pf, "%s\n", lsf_out.ci_user);
						fprintf(fp_pf, "%s\n", dnum);
						fprintf(fp_pf, "%s\n", lsf_out.ci_cset);
						fprintf(fp_pf, "%s\n", lsf_out.ci_pf);
						fprintf(fp_pf, "%d", lsf_out.ci_ui);

						fclose(fp_pf);
					}

					/* ## check for -rf expiration ## */
    				if(lsf_out.ci_rf)
					{
						if( (lsf_out.ci_rf*3600) <= ((int) duration) )
						{
							printf("\n [ RunFor duration of %d hours expired ]\n",
									lsf_out.ci_rf);
							return 1;
						}
					}

					time_dif = 0;
					uicount = 0;
				}
				count=0;
			}

			passprg[i-1]++;
			for(end = i; end > 0;end --)
			{
				for (z=0; z <i; z++)
				{
					if(passprg[i-z] == varlen) { passprg[i-z-1]++; passprg[i-z] = 0; }
				}
			}
		}
	}
	/* if we reach this point, no password matched. Try another charset or length! */
	printf("No password matched. Try another charset or length!\n");
	checkpass[0] = '\0';
	the_res(lsf_out_ptr, start_time);
	return 1;
}

/* ## begin help sub ## */

void help ()
{
	int i;
	printf("  -f <file>    File to load password from (required unless using lsf)\n");
	printf("  -u <user>    Username to load from file (required unless using lsf)\n");
	printf("  -lsf <file>  Load saved file from previous session\n");
	printf("  -lcf <file>  Load character set file (format line: <number> <characters>)\n");
	printf("  -ldf <file>  Load dictionary for use dictionary mode. (default is '/usr/share/dict/words')\n");
	printf("  -pf <file>   Save progress to file at update interval\n");
	printf("  -rf #        Amount of time in hours to run for (default infinite)\n");
	printf("  -c #         Character set from internal character set to use (default 1)\n");
	printf("  -pws #       Minimum password length (starting value, default 1)\n");
	printf("  -pwl #       Maximum password length (default %d - maximum %d)\n", DEFAULTPWLENGTH, MAXPASSWDLENGTH);
	printf("  -ui #        Console update interval (in minutes - default 10)\n");
	printf("  -v           Verbose output\n");
	printf("  -md          Dictionary crack mode, brute-force is default mode\n\n");
	printf("Internal character sets:\n");
	for (i=0;i<5;i++)
		printf("set %d: %s (%d characters)\n", i, charsets[i], (int)strlen(charsets[i]));
}

/* ## begin results sub ## */

void the_res(struct crack_input *lsf_out_ptr, struct tm start)
{
	struct crack_input lsf_out;
	memcpy(&lsf_out, lsf_out_ptr, sizeof(struct crack_input));
	time_t c_time = time(NULL);
	struct tm act_time = *localtime(&c_time);;
	int r;
	char message[8][81];		// result message
	FILE * fp_pf;				// progressfile
	char str_duration[17];
	convert(get_duration(mktime(&start)), str_duration);
	sprintf(message[0], "%s\n", FIN_IDENT);
	sprintf(message[1], "\n");

	if (lsf_out.ci_dpas[0] != '\0')
	{
		sprintf(message[2], " The password has been located.\n");
		sprintf(message[3], " Username : %s\n", lsf_out.ci_user);
		sprintf(message[4], " Password : %s\n", lsf_out.ci_dpas);
	}
	else
	{
		sprintf(message[2], " The password could not be located.\n");
		sprintf(message[3], " Username : %s\n", lsf_out.ci_user);
		sprintf(message[4], " Password : %s\n", "** unknown **");
	}

	sprintf(message[5], " Started  : %s", asctime(&start));
	sprintf(message[6], " Finished : %s", asctime(&act_time));
	sprintf(message[7], " Duration : %s\n", str_duration);

	for (r = 1; r <= 7; r++)
	{
		printf("%s", message[r]);
	}

	if(strlen(lsf_out.ci_pf))
	{	if ( (fp_pf = fopen(lsf_out.ci_pf, "w")) == NULL )
		{	printf("Error: Can't open %s!\n", lsf_out.ci_pf);
			exit(-1); }

		for (r = 0; r <=7; r++) { fprintf(fp_pf, message[r]); }
		fclose(fp_pf);
	}
}


int main(int argc, char *argv[])
{
	char *file = 0;							// filename passwordfile
	char *pass = malloc(MAXENCPWDLENGTH+1);	// encrypted password
	char *user = 0;							// username in passwordfile
	char *lsf  = 0;							// filename loadsourcefile
	char *lcf  = 0;							// filename loadcharacterset
	char *ldf  = 0;							// filename loaddictionary
	char *pf   = 0;							// filename progressfile
	int  rf    = 0;							// runtime limit
	int  chr   = 1;							// characterset
	int  pws   = 1;							// min passwordlength
	int  pwl   = DEFAULTPWLENGTH;			// max passwordlength
	int  ui    = 10;						// console update interval
	int  vo    = 0;							// verbose output
	int  md    = 0;							// mode dictionary
	int  ht    = 0;							// halt after runtime
	int  i     = 0;							// loop variable
	FILE *fp_lsf;							// loadsourcefile
	FILE *fp_file;							// passwordfile
	FILE *fp_cset;							// character set file
	char *line = malloc(255);				// tmp buffer
	char *vp_stat = malloc(255);			// last saved status
	struct crack_input lsf_out;
	int result	= 0;

	printf("\nViper modified version by pippo60gd of the original C version by Frank4DD.\nOriginal version is located in:\nhttp://www.frank4dd.com/sw/viper/\n\n");

	/* need help? */

	if ( argc == 1 ||
		(!(strcmp (argv[1], "-h"))) ||
		(!(strcmp (argv[1], "-?"))) )
		{
			help();
			exit(0);
		}

	/* */
	for (i = 1; i < argc; i++)
	{
		if (! (strcmp (argv[i], "-v")))
			vo = 1;								// set verbose option
		else if (! (strcmp (argv[i], "-ht")))
			ht = 1;								// set halt option
		else if (! (strcmp (argv[i], "-md")))
			md = 1;								// set mode dictionary option
	}

	lsf_out.ci_cset	= malloc(MAXSTR);
	lsf_out.ci_pass	= malloc(MAXENCPWDLENGTH+1);
	lsf_out.ci_dpas = malloc(MAXPASSWDLENGTH+1);
	lsf_out.ci_user	= malloc(NCHRUSER);
	lsf_out.ci_dnum	= malloc(MAXSTR);
	lsf_out.ci_pf	= malloc(MAXSTR);
	lsf_out.ci_rf	= 0;
	lsf_out.ci_pwl	= 0;
	lsf_out.ci_pws	= 0;
	lsf_out.ci_ui	= 0;
	lsf_out.ci_vo	= 0;
	lsf_out.ci_ht	= 0;
/* */

	/* process command line arguments */
	for (i = 1; i < argc; i++)
	{
		if      (! (strcmp (argv[i], "-f"  ))) { file = (argv[i+1][0] != '-') ? argv[i+1] : 0; i++;}
		else if (! (strcmp (argv[i], "-u"  ))) { user = (argv[i+1][0] != '-') ? argv[i+1] : 0; i++;}
		else if (! (strcmp (argv[i], "-c"  ))) { chr  = (argv[i+1][0] != '-') ? atoi(argv[i+1]) : 1; i++;}
		else if (! (strcmp (argv[i], "-pwl"))) { pwl  = (argv[i+1][0] != '-') ? atoi(argv[i+1]) : DEFAULTPWLENGTH; i++;}
		else if (! (strcmp (argv[i], "-ui" ))) { ui   = (argv[i+1][0] != '-') ? atoi(argv[i+1]) : 10; i++;}
		else if (! (strcmp (argv[i], "-pws"))) { pws  = (argv[i+1][0] != '-') ? atoi(argv[i+1]) : 1; i++;}
		else if (! (strcmp (argv[i], "-lsf"))) { lsf  = (argv[i+1][0] != '-') ? argv[i+1] : 0; i++;}
		else if (! (strcmp (argv[i], "-ldf"))) { ldf  = (argv[i+1][0] != '-') ? argv[i+1] : 0; i++;}
		else if (! (strcmp (argv[i], "-lcf"))) { lcf  = (argv[i+1][0] != '-') ? argv[i+1] : 0; i++;}
		else if (! (strcmp (argv[i], "-pf" ))) { pf   = (argv[i+1][0] != '-') ? argv[i+1] : 0; i++;}
		else if (! (strcmp (argv[i], "-rf" ))) { rf   = (argv[i+1][0] != '-') ? atoi(argv[i+1]) : 0; i++;}
		else if (! (strcmp (argv[i], "-v"  ))) { continue; }
		else if (! (strcmp (argv[i], "-ht" ))) { continue; }
		else if (! (strcmp (argv[i], "-md" ))) { continue; }
		else { printf("Unknown argument \"%s\": try viper -h\n", argv[i]); exit(-1); }
	}

	/* break early if calling from file */

	if ( ht )
	{
		uid_t uid = getuid();
		if (uid)
		{
			printf("You must be root to run halt option.\n");
			exit (1);
		}
	}
	
	if ( ldf && !md ) { md = 1;}
	
	if (lsf)
	{
		if ( (fp_lsf = fopen(lsf, "r+")) == NULL )
		{
			printf("Error: Can't open %s!\n", lsf);
			exit(-1);
		}

		fscanf (fp_lsf, "%s", vp_stat);

		/* check to see if run has been completed */

		if (! (strcmp (vp_stat, FIN_IDENT)))
		{
			printf("The saved run has been completed.\n");
			printf("Check %s for details.\n", lsf);
			fclose(fp_lsf); exit(-1);
		}

		/* continue otherwise */

		fscanf (fp_lsf, "%d", &lsf_out.ci_pws);
		fscanf (fp_lsf, "%d", &lsf_out.ci_pwl);
		fscanf (fp_lsf, "%s", lsf_out.ci_pass);
		fscanf (fp_lsf, "%s", lsf_out.ci_user);
		fscanf (fp_lsf, "%s", lsf_out.ci_dnum);
		fscanf (fp_lsf, "%s", lsf_out.ci_cset);
		fscanf (fp_lsf, "%s", lsf_out.ci_pf);
		fscanf (fp_lsf, "%d", &lsf_out.ci_ui);
		fclose(fp_lsf);
		lsf_out.ci_rf = rf;
		lsf_out.ci_vo = vo;
		lsf_out.ci_ht = ht;
		printf("...loaded parameters from file %s.\n", lsf);
		if (!md)
			crack_bruteforce(&lsf_out);
		else
			crack_dict(&lsf_out, ldf);
	}

	/* check for required arguments */

	if (!file)
	{
		printf("Error: Password filename required!\n"); exit(-1);
	}
	else if (!user)
	{
		printf("Error: Username required!\n"); exit(-1);
	}

	/* attempt to load account from file */

	else if ( (fp_file = fopen(file, "r")) == NULL )
	{
		printf("Error: Can't open %s!\n", file);
		exit(-1);
	}

	while ( (fscanf (fp_file, "%s", line) != EOF) )
	{
		char *result = NULL;
		if (! (strcmp (user, strtok(line, ":"))) )
		{
			result = strtok(NULL, ":");
			if (result != NULL) {
				
				if ( strlen(result) <  4 )
				{
					printf("Error: Bad password for user %s!\n", user);
					exit(-1);
				}
				strcpy(pass, result);
				printf("Found: user %s%s%s\n", user, " pw:", pass);
				break;
			}
		}
	}
	fclose(fp_file);
	if (!pass)
	{
		printf("Error: No %s%s%s!\n", user, " in ", file);
		exit(-1);
	}

	/* load character set */
	if (lcf && (!ldf && !md ))
	{
		if((fp_cset = fopen(lcf, "r")) == NULL )
		{
			printf ("Error: Can't open %s!\n", lcf);
			exit(-1);
		}
		
		while((fscanf (fp_cset, "%s", line) != EOF))
		{
			if(chr == (atoi(line)))
			{
				fscanf (fp_cset, "%s", lsf_out.ci_cset); break;
			}
		}
		
		if ( !lsf_out.ci_cset || (strlen(lsf_out.ci_cset)) < 2 )
		{
			printf("Error: Bad charset %d in %s!\n", chr, lcf); exit(-1);
		}
		else
		{
			printf("Found: Charset %d in %s\n", chr, lcf);
		}
		fclose(fp_cset);
	}
	else if (!ldf && !md )
	{
		strcpy(lsf_out.ci_cset, charsets[chr]);
		printf("Internal charset %d\n", chr);
	}

	/* write data in struct */
	lsf_out.ci_rf = rf;
	if (pf) { strcpy (lsf_out.ci_pf, pf); }
	lsf_out.ci_pws = pws;
	lsf_out.ci_pwl = pwl;
	strcpy (lsf_out.ci_pass, pass);
	strcpy (lsf_out.ci_user, user);
	lsf_out.ci_ui = ui;
	lsf_out.ci_vo = vo;
	lsf_out.ci_ht = ht;
	printf("...command line parameters loaded.\n");
	if (!md)
		result = crack_bruteforce(&lsf_out);
	else
		result = crack_dict(&lsf_out, ldf);
	if (!result)
		printf("%s", lsf_out.ci_dpas);
	free(pass);
	free(line);
	free(vp_stat);
	free(lsf_out.ci_cset);
	free(lsf_out.ci_pass);
	free(lsf_out.ci_dpas);
	free(lsf_out.ci_user);
	free(lsf_out.ci_dnum);
	free(lsf_out.ci_pf);
	printf("\nViper exiting...\n");
	return 0;
}

