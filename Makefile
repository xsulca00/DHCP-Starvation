all: dhcpstarve.cpp
	g++ -std=c++11 -O2 -Wall -Wextra -pedantic -o ipk-dhcpstarve dhcpstarve.cpp

run:
	./ipk-dhcpstarve -i enp0s3
