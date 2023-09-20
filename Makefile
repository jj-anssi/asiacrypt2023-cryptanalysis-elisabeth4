all:
	gcc -Wall -O3 -o elisabeth main.c -lm4ri -lcrypto -lgsl -lgslcblas

docker-build:
	sudo docker build -t ac2023-elisabeth4 .

docker-run:
	sudo docker run -h asiacrypt2023 -it -v .:/app ac2023-elisabeth4 bash

test:
	/bin/bash ./run-test.sh

clean:
	rm -rf lily3_10_2 /tmp/wdir *.o elisabeth
