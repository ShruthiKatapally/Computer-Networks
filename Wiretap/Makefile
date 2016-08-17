CC=g++
CPFLAGS=-g -Wall
LDFLAGS= -lpcap


SRC=wiretap.cpp
OBJ=$(SRC:.c=.o)
BIN=wiretap

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) $(LDFLAGS) -o $(BIN) $(OBJ) 


%.o:%.cpp
	$(CC) -c $(CPFLAGS) -o $@ $<  

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)
