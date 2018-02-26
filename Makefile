CFLAGS=-Wall -g
CXXFLAGS=-Wall -std=c++11 -g
LDFLAGS+=-lssl -lcrypto

.PHONY: build
build: ipmi

.PHONY: clean
clean:
	rm -f *.o ipmi

ipmi: mongoose.o main.cpp ipmi.o # ipmi.o main.o ipmi_mongoose.o client.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

run-test: ipmi
	./ipmi

test: mongoose.o test.o
	$(CXX) -o $@ $^ $(LDFLAGS)

mongoose.o: mongoose.c

ipmi.o: ipmi.cpp ipmi.h
ipmi.cpp: mongoose.h insist.h ipmi.h

mongoose.c: mongoose.h
	curl -s https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.c > $@

mongoose.h:
	curl -s https://raw.githubusercontent.com/cesanta/mongoose/master/mongoose.h > $@

insist.h:
	curl -s https://raw.githubusercontent.com/jordansissel/experiments/master/c/better-assert/insist.h > $@
