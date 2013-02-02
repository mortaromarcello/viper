viper
=====
Viper is a program to crack unix password with brute-force.
More information is on the website author: http://www.frank4dd.com/sw/viper/

	Viper modified version by pippo60gd - original version is located in:
	Viper v1.5 (Hale 05/12/2000) - C version by Frank4DD (05/22/00)
	Wiltered Fire - www.wilter.com/wf

		-f <file>    File to load password from (required unless using lsf)
		-u <user>    Username to load from file (required unless using lsf)
		-lsf <file>  Load saved file from previous session
		-pf <file>   Save progress to file at update interval
		-rf #        Amount of time in hours to run for (default infinite)
		-c #         Character set from internal character set to use (default 1)
		-pws #       Minimum password length (starting value, default 1)
		-pwl #       Maximum password length (default 8 - maximum 16)
		-ui #        Console update interval (in minutes - default 10)
		-v           Verbose output
	Internal character sets:
	set 0: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}\|;':",./<>?` (93 characters)
	set 1: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 (62 characters)
	set 2: abcdefghijklmnopqrstuvwxyz1234567890 (36 characters)
	set 3: abcdefghijklmnopqrstuvwxyz (26 characters)
	set 4: 1234567890 (10 characters)
