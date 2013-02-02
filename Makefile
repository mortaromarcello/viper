CC     = gcc
CCOPTS = -O2
CCFLAGS = -Wall -g
#LDOPTS = -s
LDFLAGS = -lssl
SRCS = viper_mod.c
OBJS = $(SRCS:%.c=%.o)
EXE = viper
all:EXE
EXE:
	$(CC) $(CCOPTS) $(CCFLAGS) -c $(SRCS)
	$(CC) $(LDFLAGS) $(OBJS) -o $(EXE)
clean:
	rm -f $(OBJS) $(EXE)
