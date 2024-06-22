all: correct_wif_errors

correct_wif_errors: correct_wif_errors.o sha-256.o base58.o ripemd160.o 
	g++ -g -o correct_wif_errors correct_wif_errors.o sha-256.o base58.o ripemd160.o -lgmp -lgmpxx 

clean:
	rm correct_wif_errors.o sha-256.o base58.o ripemd160.o

base58.o: libbase58/base58.c
	gcc -O3 -c -Ilibbase58 libbase58/base58.c

sha-256.o: sha-2/sha-256.c
	gcc -O3 -c -Isha-2 sha-2/sha-256.c

correct_wif_errors.o: correct_wif_errors.cpp
	g++ -O3 -c -Wall -Wextra -g -Ilibbase58 -Isha-2 correct_wif_errors.cpp

ripemd160.o: cpp-ripemd160/ripemd160.c
	g++ -O3 -c -Wall -Wextra -g cpp-ripemd160/ripemd160.c

test: correct_wif_errors
	./correct_wif_errors 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
	./correct_wif_errors 5HueCGU8rMjxEXxixuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
	./correct_wif_errors 5HueCGU8rMjxEXxixuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTj
	-./correct_wif_errors 5HueCGU8rMjxEXxiPuD5BDku9MkFqeZyd4d21jvhTVqvbTLvytJ
	./correct_wif_errors 5JjYhUmMs3a5jt4NfsWoyvabTPHiF5zNaZyBWDrAK3zdUQbZjmN

