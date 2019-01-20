all: targ

targ: second_preim_48_fillme.o
	gcc -o targ second_preim_48_fillme.o
second_preim_48_fillme.o: second_preim_48_fillme.c
	gcc -c -O0 second_preim_48_fillme.c -Wall -pedantic -std=c99


clean:
	rm -f *.o targ
