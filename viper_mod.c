#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <openssl/des.h>

/*                                                                    */

//#define DEBUG				0
#define DEFAULTPWLENGTH		8
#define MAXPASSWDLENGTH 	16
#define MAXENCPWDLENGTH 	13
//#define CHARSET_FILE 		"charset.ini"
#define TIMECHECK			1000000
#define FIN_IDENT			"--viper_final--"
#define SCREENWIDTH			80
#define SCREENHEIGTH		24
#define MAXSTR				255
#define NCHRUSER			80

char *charsets[] = {
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}\\|;\':\",./<>?`",
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
		"abcdefghijklmnopqrstuvwxyz1234567890",
		"abcdefghijklmnopqrstuvwxyz",
		"1234567890"
};

struct crack_input
{
	char *ci_user;						// username
	char *ci_pass;						// encrypted password
	char *ci_cset;						// characterset to use
	char ci_rf;							// runtime limit
	int  ci_pwl;						// password max length
	int  ci_pws;						// password min length
	int  ci_ui;							// console update interval
	char *ci_dnum;						// status for each digit
	char *ci_pf;						// progressfile name
	int  ci_vo;							// verbose output
};

// struct    crack_input lsf_out;
struct	tm start_time, last_time;		// time structs
char	checkpass[17];					// cleartext passphrase
char	message[7][81];				// result message
char	time_done[17];					// passed time
char	time_togo[17];					// calculated time to run
time_t	read_time;						// actual time
FILE *	fp_pf;							// progressfile

/*                                                                    */

void the_res(struct crack_input *, char *, struct tm);
void help (void);
void convert(double, char *);
void crack(struct crack_input *);
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

void crack(struct crack_input *lsf_out_ptr)
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
	char * pass;

	/* debug only */
#ifdef DEBUG
	printf("user>%s pass>%s cset>%s rf>%d pwl>%d pws>%d ui>%d dnum>%s pf>%s\n",
	lsf_out.ci_user,
	lsf_out.ci_pass, lsf_out.ci_cset, rf,
	lsf_out.ci_pwl, lsf_out.ci_pws, ui,
	lsf_out.ci_dnum, lsf_out.ci_pf);
#endif
	/* fine debug */

	printf("Character set is %d chars long.\nCharacters used:%s\n", varlen, lsf_out.ci_cset);

	/* get current time */
	time(&read_time);
	start_time = *localtime(&read_time);
	last_time = start_time;
	printf("Starting crack on: %s", asctime(&start_time));

	/* go on with the show */
	if (strlen(lsf_out.ci_dnum))
	{
		passprg[0]=atoi(strtok(lsf_out.ci_dnum, ",")); i=1;
		printf("Saved progress is: %d (%c)", passprg[0], lsf_out.ci_cset[passprg[0]]);
		while ( (pass = strtok(NULL, ",")) )
		{
			if (pass && atoi(pass) < 128){passprg[i]=atoi(pass);}
			printf(" %d (%c)", passprg[i], lsf_out.ci_cset[passprg[i]]); i++;
		}
		printf("\n");
		startpws = i;
		for ( j=i; j<((int) lsf_out.ci_pwl); j++ ) { passprg[j] = 0;}
		on = 1;
	}

	strncat(salt, lsf_out.ci_pass, 2);

	/* debug only */
#ifdef DEBUG
	printf("Salt of the password %13s is: %s\n", lsf_out.ci_pass, salt);
#endif

	/* make new password */
	for ( i = startpws; i <= ((int) lsf_out.ci_pwl); i++ )
	{
		if (on) { on = 0; }
		else
		{
			for ( j=0; j<((int) lsf_out.ci_pwl); j++ ) { passprg[j] = 0;}
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
#ifdef DEBUG
				printf("We got it!!!! ----> %s\n", checkpass);
#endif
				the_res(lsf_out_ptr, checkpass, start_time);
			}

			/* debug only */
#ifdef DEBUG
			printf("count: %d\n", count);
#endif

			/* Time check */
			if (count == TIMECHECK)
			{
				static struct tm act_time;
				double time_dif;

				time_loop++;

				time(&read_time);
				act_time=*localtime(&read_time);
				time_dif = difftime(mktime(&act_time), mktime(&last_time));
				uicount = uicount + count;

				/* debug only */
#ifdef DEBUG
				printf("[ act: %s | last: %s | diff: %d | uicount: %d ]\n",
							asctime(&act_time), asctime(&last_time), time_dif, uicount);
#endif

				/* update interval check - calculate duration and cps */
				if (time_dif >= ui)
				{
					double duration;

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
						if( (lsf_out.ci_rf*3600) >= ((int) duration) )
						{
							printf("\n [ RunFor duration of %d hours expired ]\n",
									lsf_out.ci_rf);
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
	checkpass[0] = '\0';
	the_res(lsf_out_ptr, checkpass, start_time);
}

int main(int argc, char *argv[])
{
	char *file = 0;							// filename passwordfile
	char *pass = malloc(MAXENCPWDLENGTH+1);	// encrypted password
	char *user = 0;							// username in passwordfile
	char *lsf  = 0;							// filename loadsourcefile
	char *pf   = 0;							// filename progressfile
	int  rf    = 0;							// runtime limit
	int  chr   = 1;							// characterset
	int  pws   = 1;							// min passwordlength
	int  pwl   = DEFAULTPWLENGTH;			// max passwordlength
	int  ui    = 10;						// console update interval
	int  vo    = 0;							// verbose output
	int  i     = 0;							// loop variable
	FILE *fp_lsf;							// loadsourcefile
	FILE *fp_file;							// passwordfile
//	FILE *fp_cset;							// character set file
	char *line = malloc(255);				// tmp buffer
	char *vp_stat = malloc(255);			// last saved status
	struct crack_input lsf_out;

	printf("\nViper modified version by pippo60gd - original version is located in:");
	printf("\nViper v1.5 (Hale 05/12/2000) - C version by Frank4DD (05/22/00)\n");
	printf("Wiltered Fire - www.wilter.com/wf\n\n");

	/* need help? */

	if ( argc == 1 ||
		(!(strcmp (argv[1], "-h"))) ||
		(!(strcmp (argv[1], "-?"))) )
		{
			help();
			exit(0);
		}

	/* verbose output on? */
	for (i = 1; i < argc; i++)
	{
		if (! (strcmp (argv[i], "-v")))
			vo = 1;
	}

	if (vo)
	{
		if ( (argc != 2) && (argc != 4) && (argc != 6) &&
			(argc != 8) && (argc != 10) && (argc != 12)
			&& (argc != 14) && (argc != 16) )
		{
			printf("missing value for argument: try viper -h\n");
			exit(-1);
		}
	}
	else
	{
		if ( (argc != 1) && (argc != 3) && (argc != 5) &&
			(argc != 7) && (argc != 9) && (argc != 11)
			&& (argc != 13) && (argc != 15) )
		{
			printf("missing value for argument: try viper -h\n");
			exit(-1);
		}
	}

/* */
	lsf_out.ci_cset	= malloc(MAXSTR);
	lsf_out.ci_pass	= malloc(MAXENCPWDLENGTH+1);
	lsf_out.ci_user	= malloc(NCHRUSER);
	lsf_out.ci_dnum	= malloc(MAXSTR);
	lsf_out.ci_pf	= malloc(MAXSTR);
	lsf_out.ci_rf	= 0;
	lsf_out.ci_pwl	= 0;
	lsf_out.ci_pws	= 0;
	lsf_out.ci_ui	= 0;
	lsf_out.ci_vo	= 0;
/* */

	/* process command line arguments */
	for (i = 1; i < argc; i++)
	{
		if      (! (strcmp (argv[i], "-f"  ))) { file =      argv[i+1] ; i++;}
		else if (! (strcmp (argv[i], "-u"  ))) { user =      argv[i+1] ; i++;}
		else if (! (strcmp (argv[i], "-c"  ))) { chr  = atoi(argv[i+1]); i++;}
		else if (! (strcmp (argv[i], "-pwl"))) { pwl  = atoi(argv[i+1]); i++;}
		else if (! (strcmp (argv[i], "-ui" ))) { ui   = atoi(argv[i+1]); i++;}
		else if (! (strcmp (argv[i], "-pws"))) { pws  = atoi(argv[i+1]); i++;}
		else if (! (strcmp (argv[i], "-lsf"))) { lsf  =      argv[i+1] ; i++;}
		else if (! (strcmp (argv[i], "-pf" ))) { pf   =      argv[i+1] ; i++;}
		else if (! (strcmp (argv[i], "-rf" ))) { rf   = atoi(argv[i+1]); i++;}
		else if (! (strcmp (argv[i], "-v"  ))) { continue; }
		else { printf("Unknown argument \"%s\": try viper -h\n", argv[i]); exit(-1); }
	}

	/* break early if calling from file */

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
		lsf_out.ci_rf = 0;
		lsf_out.ci_vo = vo;
		printf("...loaded parameters from file %s.\n", lsf);
		crack(&lsf_out);
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
	strcpy(lsf_out.ci_cset, charsets[chr]);
	printf("Charset %d\n", chr);

/*
	if ( (fp_cset = fopen(CHARSET_FILE, "r")) == NULL )
	{
		printf("Error: Can't open %s!\n", CHARSET_FILE);
		exit(-1);
	}

	while ( (fscanf (fp_cset, "%s", line) != EOF) )
	{
		if ( chr == (atoi(line)) )
		{
			fscanf (fp_cset, "%s", lsf_out.ci_cset); break;
		}
	}

	if ( !lsf_out.ci_cset || (strlen(lsf_out.ci_cset)) < 2 )
	{
		printf("Error: Bad charset %d in %s!\n", chr, CHARSET_FILE); exit(-1);
	}
	else
	{
		printf("Found: Charset %d in %s\n", chr, CHARSET_FILE);
	}

	fclose(fp_cset);
*/

	/* write data in struct */
	lsf_out.ci_rf = rf;
	if (pf) { strcpy (lsf_out.ci_pf, pf); }
	lsf_out.ci_pws = pws;
	lsf_out.ci_pwl = pwl;
	strcpy (lsf_out.ci_pass, pass);
	strcpy (lsf_out.ci_user, user);
	lsf_out.ci_ui = ui;
	lsf_out.ci_vo = vo;
	printf("...command line parameters loaded.\n");
	crack(&lsf_out);

	free(pass);
	free(line);
	free(vp_stat);
	free(lsf_out.ci_cset);
	free(lsf_out.ci_pass);
	free(lsf_out.ci_user);
	free(lsf_out.ci_dnum);
	free(lsf_out.ci_pf);
	return 0;
}

/* ######## start subs ############### */

/* ## begin help sub ## */

void help ()
{
	printf("\t-f <file>    File to load password from (required unless using lsf)\n");
	printf("\t-u <user>    Username to load from file (required unless using lsf)\n");
	printf("\t-lsf <file>  Load saved file from previous session\n");
	printf("\t-pf <file>   Save progress to file at update interval\n");
	printf("\t-rf #        Amount of time in hours to run for (default infinite)\n");
	printf("\t-c #         Character set from internal character set to use (default 1)\n");
	printf("\t-pws #       Minimum password length (starting value, default 1)\n");
	printf("\t-pwl #       Maximum password length (default %d - maximum %d)\n",
			  DEFAULTPWLENGTH, MAXPASSWDLENGTH);
	printf("\t-ui #        Console update interval (in minutes - default 10)\n");
	printf("\t-v           Verbose output\n");
}

/* ## begin results sub ## */

void the_res(struct crack_input *lsf_out_ptr, char * endpass, struct tm start)
{
	struct crack_input lsf_out;
	memcpy(&lsf_out, lsf_out_ptr, sizeof(struct crack_input));
	static struct tm act_time;
	double end_time;
	int r;
	char time_total[17];

	time(&read_time);
	act_time=*localtime(&read_time);
	end_time = difftime(mktime(&act_time), mktime(&start));
	convert(end_time, time_total);

	sprintf(message[0], "%s\n", FIN_IDENT);
	sprintf(message[1], "\n");

	if (endpass[0] != '\0')
	{
		sprintf(message[2], " The password has been located.\n");
		sprintf(message[3], " Username : %s\n", lsf_out.ci_user);
		sprintf(message[4], " Password : %s\n", endpass);
	}
	else
	{
		sprintf(message[2], " The password could not be located.\n");
		sprintf(message[3], " Username : %s\n", lsf_out.ci_user);
		sprintf(message[4], " Password : %s\n", "** unknown **");
	}

	sprintf(message[5], " Started  : %s", asctime(&start));
	sprintf(message[6], " Finished : %s", asctime(&act_time));
	sprintf(message[7], " Duration : %s\n", time_done);

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

	printf("\nViper exiting...\n");
	exit(0);
}

