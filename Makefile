CC     = gcc
CCOPTS = -O2
CCFLAGS = -Wall -g
#LDOPTS = -s
LDFLAGS = -lssl
viper:
	$(CC) $(CCOPTS) $(CCFLAGS) -c viper_mod.c
	$(CC) $(LDFLAGS) viper_mod.o -o viper
clean:
	rm -f *.o viper
