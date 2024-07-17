all: correct_wif_errors

correct_wif_errors: correct_wif_errors.o sha-256.o base58.o ripemd160.o sha2.o sha256.o sha512.o bech32.o segwit_addr.o
	g++ -g -o correct_wif_errors correct_wif_errors.o sha-256.o base58.o ripemd160.o sha2.o sha256.o sha512.o bech32.o segwit_addr.o -lgmp -lgmpxx 

clean:
	rm correct_wif_errors.o sha-256.o base58.o ripemd160.o sha2.o sha256.o sha512.o bech32.o segwit_addr.o

base58.o: libbase58/base58.c
	gcc -c -Ilibbase58 libbase58/base58.c

sha-256.o: sha-2/sha-256.c
	gcc -c -Isha-2 sha-2/sha-256.c

correct_wif_errors.o: correct_wif_errors.cpp
	g++ -c -Wall -Wextra -g -Ilibbase58 -Isha-2 correct_wif_errors.cpp

ripemd160.o: cpp-ripemd160/ripemd160.c
	g++ -c -Wall -Wextra -g cpp-ripemd160/ripemd160.c

sha2.o: sha/src/sha2.cpp
	g++ -c -g sha/src/sha2.cpp

sha256.o: hmac-cpp/sha256.cpp
	g++ -Wall -Wextra -g -c hmac-cpp/sha256.cpp

sha512.o: hmac-cpp/sha512.cpp
	g++ -Wall -Wextra -g -c hmac-cpp/sha512.cpp

bech32.o: bech32/ref/c++/bech32.cpp
	g++ -Wall -Wextra -g -c bech32/ref/c++/bech32.cpp

segwit_addr.o: bech32/ref/c++/segwit_addr.cpp
	g++ -Wall -Wextra -g -c bech32/ref/c++/segwit_addr.cpp

test: correct_wif_errors
	./correct_wif_errors 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
	./correct_wif_errors 5HueCGU8rMjxEXxixuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
	./correct_wif_errors 5HueCGU8rMjxEXxixuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTj
	./correct_wif_errors bc1qy7m6d8mh5em8drkurgu6m46p6xmlqar63kl4vv
	./correct_wif_errors abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
	./correct_wif_errors egg face
	./correct_wif_errors L2hPS1vMTd37haEcTeuXUr2ssn5VcD68j8KoLJ71rUkNXWHneTqw
	./correct_wif_errors 5JjYhUmMs3a5jt4NfsWoyvabTPHiF5zNaZyBWDrAK3zdUQbZjmN
